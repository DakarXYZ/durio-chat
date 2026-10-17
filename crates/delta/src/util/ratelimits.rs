use revolt_ratelimits::ratelimiter::RatelimitResolver;
use rocket::{http::Method, Request};

pub struct DeltaRatelimits;

impl<'a> RatelimitResolver<Request<'a>> for DeltaRatelimits {
    fn resolve_bucket<'r>(&self, request: &'r Request<'_>) -> (&'r str, Option<&'r str>) {
        let (segment, resource, extra) = (
            request.routed_segment(0),
            request.routed_segment(1),
            request.routed_segment(2),
        );

        if let Some(segment) = segment {
            #[allow(clippy::redundant_locals)]
            let resource = resource;

            let method = request.method();
            match (segment, resource, method) {
                ("users", target, Method::Patch) => ("user_edit", target),
                ("users", _, _) => {
                    if let Some("default_avatar") = extra {
                        return ("default_avatar", None);
                    }

                    ("users", None)
                }
                ("bots", _, _) => ("bots", None),
                ("channels", Some(id), _) => {
                    if request.method() == Method::Post {
                        if let Some("messages") = extra {
                            return ("messaging", Some(id));
                        }
                    }

                    ("channels", Some(id))
                }
                ("servers", Some(id), _) => ("servers", Some(id)),
                ("auth", _, _) => {
                    if request.method() == Method::Delete {
                        ("auth_delete", None)
                    } else {
                        ("auth", None)
                    }
                }
                // dur.io fork: all devices of a user share these buckets
                ("e2ee", Some("keys"), _) => ("e2ee_keys", None),
                ("e2ee", Some("to_device"), _) => ("e2ee_to_device", None),
                ("e2ee", Some("backup" | "secrets"), _) => ("e2ee_backup", None),
                ("swagger", _, _) => ("swagger", None),
                ("safety", Some("report"), _) => ("safety_report", Some("report")),
                ("safety", _, _) => ("safety", None),
                _ => ("any_dlta", None),
            }
        } else {
            ("any_dlta", None)
        }
    }

    fn resolve_bucket_limit(&self, bucket: &str) -> u32 {
        match bucket {
            "user_edit" => 2,
            "users" => 20,
            "bots" => 10,
            "messaging" => 10,
            "channels" => 15,
            "servers" => 5,
            "auth" => 15,
            "auth_delete" => 255,
            "default_avatar" => 255,
            "swagger" => 100,
            "safety" => 15,
            "safety_report" => 3,
            "e2ee_keys" => 30,
            "e2ee_to_device" => 60,
            // Restoring a key backup takes many requests
            "e2ee_backup" => 60,
            _ => 20,
        }
    }
}

#[cfg(test)]
mod tests {
    use revolt_ratelimits::ratelimiter::RatelimitResolver;
    use rocket::{
        Request,
        local::asynchronous::Client,
        request::{FromRequest, Outcome},
    };

    use super::DeltaRatelimits;

    /// Bucket and its limit as resolved for the request
    struct Bucket(String);

    #[rocket::async_trait]
    impl<'r> FromRequest<'r> for Bucket {
        type Error = ();

        async fn from_request(request: &'r Request<'_>) -> Outcome<Self, ()> {
            let (bucket, _) = DeltaRatelimits.resolve_bucket(request);
            let limit = DeltaRatelimits.resolve_bucket_limit(bucket);
            Outcome::Success(Bucket(format!("{bucket} {limit}")))
        }
    }

    #[rocket::get("/<_path..>")]
    fn probe(_path: std::path::PathBuf, bucket: Bucket) -> String {
        bucket.0
    }

    #[rocket::async_test]
    async fn e2ee_buckets() {
        let client = Client::tracked(rocket::build().mount("/", rocket::routes![probe]))
            .await
            .unwrap();

        for (path, expected) in [
            ("/e2ee/keys/upload", "e2ee_keys 30"),
            ("/e2ee/keys/count", "e2ee_keys 30"),
            ("/e2ee/to_device/txn", "e2ee_to_device 60"),
            ("/e2ee/to_device", "e2ee_to_device 60"),
            ("/e2ee/backup/keys", "e2ee_backup 60"),
            ("/e2ee/secrets/m.megolm_backup.v1", "e2ee_backup 60"),
            ("/e2ee/unknown", "any_dlta 20"),
        ] {
            let response = client.get(path).dispatch().await;
            assert_eq!(response.into_string().await.unwrap(), expected, "{path}");
        }
    }
}
