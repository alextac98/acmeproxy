use super::{check_order_policy, protocol::validate_csr};
use crate::{App, certificates, now, store};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus, RetryPolicy,
};
use sqlx::Row;
use std::time::Duration;

async fn phase(app: &App, id: &str, phase: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        app.healthy.load(std::sync::atomic::Ordering::SeqCst),
        "configuration needs restart"
    );
    check_order_policy(app, id).await?;
    sqlx::query("UPDATE acme_orders SET phase=?,updated_at=? WHERE id=? AND state='processing'")
        .bind(phase)
        .bind(now())
        .bind(id)
        .execute(&app.db)
        .await?;
    Ok(())
}

pub(super) async fn issue(
    app: &App,
    id: &str,
    account: Account,
    resolver: &hickory_resolver::TokioResolver,
) -> anyhow::Result<()> {
    phase(app, id, "Requesting certificate from Let's Encrypt").await?;
    let row = sqlx::query("SELECT domains,csr,upstream_url FROM acme_orders WHERE id=?")
        .bind(id)
        .fetch_one(&app.db)
        .await?;
    let domains: Vec<String> = serde_json::from_str(row.get("domains"))?;
    let csr: Vec<u8> = row.try_get("csr")?;
    let public_key = validate_csr(&csr, &domains)?;
    let mut order = if let Some(url) = row.get::<Option<String>, _>("upstream_url") {
        account.order(url).await?
    } else {
        let identifiers = domains
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect::<Vec<_>>();
        let order = account.new_order(&NewOrder::new(&identifiers)).await?;
        // The CSR is already durable. Persist the upstream URL before modifying DNS.
        sqlx::query("UPDATE acme_orders SET upstream_url=?,updated_at=? WHERE id=?")
            .bind(order.url())
            .bind(now())
            .bind(id)
            .execute(&app.db)
            .await?;
        order
    };
    anyhow::ensure!(
        order.state().status != OrderStatus::Invalid,
        "upstream order is invalid"
    );
    if order.state().status == OrderStatus::Pending {
        let mut authorizations = order.authorizations();
        while let Some(auth) = authorizations.next().await {
            let mut auth = auth?;
            if auth.status == AuthorizationStatus::Valid {
                continue;
            }
            anyhow::ensure!(
                auth.status == AuthorizationStatus::Pending,
                "upstream authorization failed"
            );
            let mut challenge = auth
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| anyhow::anyhow!("no DNS-01 challenge offered"))?;
            let identifier = challenge.identifier().to_string();
            let name = identifier.strip_prefix("*.").unwrap_or(&identifier);
            anyhow::ensure!(
                domains
                    .iter()
                    .any(|d| d.strip_prefix("*.").unwrap_or(d) == name),
                "unexpected CA identifier"
            );
            let fqdn = format!("_acme-challenge.{name}");
            let value = challenge.key_authorization().dns_value();
            phase(app, id, "Publishing DNS validation").await?;
            let job = certificates::present(app, id, &fqdn, &value).await?;
            certificates::wait_present(app, &job).await?;
            phase(app, id, "Waiting for DNS propagation").await?;
            certificates::wait_dns(resolver, &fqdn, &value).await?;
            phase(app, id, "Validating domain with Let's Encrypt").await?;
            challenge.set_ready().await?;
        }
        anyhow::ensure!(
            order.poll_ready(&RetryPolicy::default()).await? == OrderStatus::Ready,
            "upstream validation failed"
        );
    }
    phase(app, id, "Finalizing the client's CSR").await?;
    if order.state().status == OrderStatus::Ready {
        order.finalize_csr(&csr).await?;
    }
    let chain = order.poll_certificate(&RetryPolicy::default()).await?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid certificate PEM"))?;
    let cert = pem
        .parse_x509()
        .map_err(|_| anyhow::anyhow!("invalid certificate"))?;
    anyhow::ensure!(
        cert.public_key().raw == public_key && cert.validity().not_after.timestamp() > now(),
        "issued certificate does not match client key or is expired"
    );
    let san = cert
        .subject_alternative_name()?
        .ok_or_else(|| anyhow::anyhow!("missing certificate domains"))?;
    let mut names = Vec::new();
    for name in &san.value.general_names {
        match name {
            x509_parser::extensions::GeneralName::DNSName(name) => {
                names.push(name.to_ascii_lowercase())
            }
            _ => anyhow::bail!("unexpected certificate identifier"),
        }
    }
    names.sort();
    names.dedup();
    anyhow::ensure!(
        names == domains,
        "issued certificate domains do not match order"
    );
    let _guard = app.mutation.lock().await;
    phase(app, id, "Issued").await?;
    let mut tx = app.db.begin().await?;
    let result = sqlx::query("UPDATE acme_orders SET state='valid',fullchain=?,certificate_der=?,error=NULL,updated_at=? WHERE id=? AND state='processing'")
        .bind(chain).bind(&pem.contents).bind(now()).bind(id).execute(&mut *tx).await?;
    anyhow::ensure!(result.rows_affected() == 1, "order was cancelled");
    sqlx::query("INSERT INTO audit(at,actor,action,target,outcome) VALUES(?,'acme-worker','acme.certificate_issued',?,'success')").bind(now()).bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn process_one(app: &App) -> anyhow::Result<bool> {
    process_one_with(app, |id, staging| async move {
        let account = certificates::account(app, staging).await?;
        let mut builder = hickory_resolver::TokioResolver::builder_tokio()?;
        builder.options_mut().cache_size = 0;
        issue(app, &id, account, &builder.build()).await
    })
    .await
}

pub(super) async fn process_one_with<F, Fut>(app: &App, perform: F) -> anyhow::Result<bool>
where
    F: FnOnce(String, bool) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let (id, staging) = {
        let _guard = app.mutation.lock().await;
        anyhow::ensure!(
            app.healthy.load(std::sync::atomic::Ordering::SeqCst),
            "configuration needs restart"
        );
        sqlx::query("UPDATE acme_orders SET state='invalid',error='Order expired',updated_at=? WHERE state IN ('pending','ready','processing') AND expires_at<=?").bind(now()).bind(now()).execute(&app.db).await?;
        // Cleanup remains durable even when an order expires during downtime.
        sqlx::query("UPDATE challenges SET state='cleanup_pending',operation='cleanup',attempts=0,next_attempt=?,updated_at=? WHERE client_id IN (SELECT id FROM acme_orders WHERE state IN ('invalid','valid')) AND state IN ('active','present_pending')")
            .bind(now()).bind(now()).execute(&app.db).await?;
        let row = sqlx::query("SELECT id,staging FROM acme_orders WHERE state='processing' AND next_attempt<=? ORDER BY next_attempt,created_at LIMIT 1").bind(now()).fetch_optional(&app.db).await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let id: String = row.get("id");
        sqlx::query(
            "UPDATE acme_orders SET attempts=attempts+1,next_attempt=?+30,updated_at=? WHERE id=?",
        )
        .bind(now())
        .bind(now())
        .bind(&id)
        .execute(&app.db)
        .await?;
        (id, row.get::<bool, _>("staging"))
    };
    let result =
        tokio::time::timeout(Duration::from_secs(1200), perform(id.clone(), staging)).await;
    certificates::cleanup(app, &id).await?;
    if !matches!(result, Ok(Ok(()))) {
        let _guard = app.mutation.lock().await;
        let row = sqlx::query("SELECT attempts,phase FROM acme_orders WHERE id=?")
            .bind(&id)
            .fetch_one(&app.db)
            .await?;
        let attempts: i64 = row.get("attempts");
        let unauthorized = check_order_policy(app, &id).await.is_err();
        let state = if attempts >= 3 || unauthorized {
            "invalid"
        } else {
            "processing"
        };
        let message = if unauthorized {
            "Order is no longer authorized".to_string()
        } else {
            format!(
                "Issuance failed during {}. Check provider access and DNS propagation.",
                row.get::<String, _>("phase").to_lowercase()
            )
        };
        sqlx::query("UPDATE acme_orders SET state=?,error=?,next_attempt=?,updated_at=? WHERE id=? AND state='processing'").bind(state).bind(message).bind(now()+30*attempts).bind(now()).bind(&id).execute(&app.db).await?;
        store::audit(&app.db, "acme-worker", "acme.issuance_attempt", &id, state).await?;
    }
    Ok(true)
}
