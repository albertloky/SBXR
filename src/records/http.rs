//! Typed, secret-free views of current HTTP operation authority.
use super::*;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpOperation {
    Enablement {
        checkpoint: u32,
        target: ServingAuthority,
    },
    Rotation {
        checkpoint: String,
        direction: ChangeDirection,
        source: ServingAuthority,
        target: ServingAuthority,
    },
    Repair {
        checkpoint: String,
        direction: ChangeDirection,
        source: ServingAuthority,
        target: Option<ServingAuthority>,
    },
}
impl OwnershipRecord {
    pub fn http_operation(&self) -> Result<Option<HttpOperation>, RecordError> {
        if let Some(e) = &self.0.subscription_enablement {
            if !e.resources.as_ref().is_some_and(|r| r.http) {
                return Err(RecordError);
            }
            return Ok(Some(HttpOperation::Enablement {
                checkpoint: e.checkpoint,
                target: ServingAuthority::http_digest(&e.link_id, &e.credential_sha256)?,
            }));
        }
        if let Some(r) = &self.0.subscription_rotation {
            if !r.source.http || !r.target.http {
                return Err(RecordError);
            }
            return Ok(Some(HttpOperation::Rotation {
                checkpoint: r.checkpoint.clone(),
                direction: if r.direction == "forward" {
                    ChangeDirection::Forward
                } else {
                    ChangeDirection::Cleanup
                },
                source: ServingAuthority(r.source.clone()),
                target: ServingAuthority(r.target.clone()),
            }));
        }
        if let Some(r) = &self.0.subscription_repair {
            if !r.source.http || r.correction != "restart owned serving runtime" {
                return Err(RecordError);
            }
            return Ok(Some(HttpOperation::Repair {
                checkpoint: r.checkpoint.clone(),
                direction: if r.direction == "forward" {
                    ChangeDirection::Forward
                } else {
                    ChangeDirection::Cleanup
                },
                source: ServingAuthority(r.source.clone()),
                target: r.target.clone().map(ServingAuthority),
            }));
        }
        if self.pending_change().is_some() {
            return Err(RecordError);
        }
        Ok(None)
    }
    pub fn subscription_compromised(&self) -> bool {
        self.0.subscription_compromised
    }
}
impl ServingAuthority {
    pub fn state_bytes(&self) -> Result<Vec<u8>, RecordError> {
        #[derive(serde::Serialize)]
        struct State<'a> {
            schema: u32,
            serving: &'a super::authority::WireServing,
        }
        super::encode(&State {
            schema: 1,
            serving: &self.0,
        })
    }
}
