// #[allow(dead_code)]
use actix_web::{App, HttpResponse, HttpServer, Responder, body, web};
use actix_multipart::Multipart;
use futures_util::{StreamExt, TryStreamExt};
use actix_web::middleware::Logger;
use serde::{Serialize,Deserialize};
use aes_gcm::{
    Aes256Gcm, Nonce, aead::{Aead, KeyInit,OsRng}, aes
};
use std::env;
// use rand_core::OsRng;
use typenum::U12;
use rand::Rng;
use mdns_sd::{ServiceDaemon,ServiceInfo};
use tokio::{fs, io::AsyncWriteExt};
use std::{fmt::format, iter::Copied, ops::Mul, path, sync::{Arc, Mutex}, vec};
use std::collections::HashMap;
use std::path::Path;
use std::io::Write;


#[derive(Serialize,Deserialize)]
struct AuthRequest{
    username:String,    
    password:String
}
#[derive(Serialize,Deserialize)]
struct AuthResponse{
    token:String
}

#[derive(Serialize)]
struct SessionResponse {
    username: String,
}

struct AppState {
    auth_tokens: Arc<Mutex<HashMap<String,String>>>,
    encryption_key:Aes256Gcm,
}

async fn index() -> impl Responder{
    match fs::read_to_string("frontend.html").await {
        Ok(html) => HttpResponse::Ok().content_type("text/html").body(html),
        Err(_) => HttpResponse::InternalServerError().body("Frontend file not found."),
    }
}


async fn authenticate(
    req: web::Json<AuthRequest>,
    state:web::Data<AppState>,
) -> impl Responder{
    if req.username == "admin" && req.password == "password"{
        // Start each authenticated use with a fresh upload set.
        if clear_uploads_dir().await.is_err() {
            return HttpResponse::InternalServerError().body("Failed to reset uploads");
        }

        let token = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(32)
                .map(|x|char::from(x))
                .collect::<String>();
        
        state.auth_tokens.lock().unwrap().insert(token.clone(), req.username.clone());
        
        HttpResponse::Ok().json(AuthResponse{token})
    }else {
        HttpResponse::Unauthorized().finish()
    }

}

fn authenticated_username(
    req: &actix_web::HttpRequest,
    state: &web::Data<AppState>,
) -> Option<String> {
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;
    let token = auth_str.strip_prefix("Bearer ")?;
    state.auth_tokens.lock().unwrap().get(token).cloned()
}

fn authenticated_token(
    req: &actix_web::HttpRequest,
    state: &web::Data<AppState>,
) -> Option<String> {
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;
    let token = auth_str.strip_prefix("Bearer ")?.to_string();
    if state.auth_tokens.lock().unwrap().contains_key(&token) {
        Some(token)
    } else {
        None
    }
}

async fn session(
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Some(username) = authenticated_username(&req, &state) {
        return HttpResponse::Ok().json(SessionResponse { username });
    }

    HttpResponse::Unauthorized().finish()
}

async fn logout(
    state: web::Data<AppState>,
    req: actix_web::HttpRequest,
) -> impl Responder {
    if let Some(token) = authenticated_token(&req, &state) {
        state.auth_tokens.lock().unwrap().remove(&token);
        if clear_uploads_dir().await.is_err() {
            return HttpResponse::InternalServerError().body("Failed to clear uploads");
        }
        return HttpResponse::Ok().finish();
    }

    HttpResponse::Unauthorized().finish()
}

async fn upload_file(
    mut payload: Multipart,
    state : web::Data<AppState>,
    req: actix_web::HttpRequest
) -> impl Responder{    
    if authenticated_username(&req, &state).is_some() {
        let mut files_saved = Vec::new();

        while let Ok(Some(mut field)) = payload.try_next().await {
            if let Some(content_disposition) = field.content_disposition(){
                let file_name = if let Some(content_disposition) = field.content_disposition(){
                    content_disposition.get_filename().unwrap_or("unnamed").to_string()
                }else {
                    continue;
                };
                let mut data = Vec::new();
                while let Some(chunck) = field.next().await{
                    let chunck = chunck.unwrap();
                    data.extend_from_slice(&chunck);
                }
                let nonce_bytes = rand::thread_rng().r#gen::<[u8;12]>();
                let nonce = Nonce::from(nonce_bytes);

                let ciphertext = state.encryption_key
                                                                            .encrypt(&nonce, data.as_ref()).unwrap();
                
                let mut encrypted_data = Vec::new();
                encrypted_data.extend_from_slice(&nonce_bytes);
                encrypted_data.extend_from_slice(&ciphertext);

                let file_path = format!("uploads/{}",file_name);
                let mut file = fs::File::create(&file_path).await.unwrap();
                file.write_all(&encrypted_data).await.unwrap();
                files_saved.push(file_name);
            }
        }

        return HttpResponse::Ok().json(files_saved);
    }
    HttpResponse::Unauthorized().finish()
}

async fn list_files(
    state : web::Data<AppState>,
    req:actix_web::HttpRequest
) -> impl Responder{
    if authenticated_username(&req, &state).is_some() {
        let mut files = Vec::new();
        let mut entries = fs::read_dir("uploads").await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap(){
            if let Some(file_name) = entry.file_name().to_str(){
                files.push(file_name.to_string());
            }
        }

        return HttpResponse::Ok().json(files)
    }
    HttpResponse::Unauthorized().finish()
}


async fn download_file(
    path:web::Path<String>,
    state : web::Data<AppState>,
    req : actix_web::HttpRequest
) -> impl Responder{
    if authenticated_username(&req, &state).is_some() {
        let file_name = path.as_str();
        let file_path = format!("uploads/{}",file_name);
        if Path::new(&file_path).exists(){
            let encrypted_data = fs::read(&file_path).await.unwrap();
            if encrypted_data.len() <12 {
                return HttpResponse::InternalServerError().finish();
            }
            let (nonce_bytes,ciphertext) = encrypted_data.split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);

            return match state.encryption_key.decrypt(nonce, ciphertext){
                Ok(decrypted_data) => {
                    HttpResponse::Ok()
                    .content_type("application/octet-stram")
                    .append_header((
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"",file_name),
                    
                    )).body(decrypted_data)
                }
                Err(_) => HttpResponse::InternalServerError().body("Decryption Failed"),
            };
        }

        return HttpResponse::NotFound().body("File Not Found");
    }

    HttpResponse::Unauthorized().finish()

}

async fn clear_uploads_dir() -> std::io::Result<()> {
    fs::create_dir_all("uploads").await?;
    let mut entries = fs::read_dir("uploads").await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let metadata = entry.metadata().await?;

        if metadata.is_file() {
            fs::remove_file(path).await?;
        }
    }

    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    clear_uploads_dir().await?;
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);

    let auth_tokens = Arc::new(Mutex::new(HashMap::new()));
    let state = web::Data::new(AppState{
        auth_tokens :auth_tokens.clone(),
        encryption_key:cipher
    });

let hostname = format!("{}.local.", 
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "SecureFileShare".to_string())
);
    let mdns = ServiceDaemon::new().expect("Failed to create mDNS daemon");
    let service_info = ServiceInfo::new(
    "_fileshare._tcp.local.",     // Service type
    "SecureFileShare",             // Instance name
    &hostname,                     // Hostname (use the variable you created!)
    "",                            // IP address (empty is fine)
    8080,                          // Port
    None                           // TXT records
    ).expect("Invalid Service Info");
    
    mdns.register(service_info).expect("failed to register mdns servifce");

    println!("NearShare-rs starting at port 8080");
    println!("use username:admin password:password");


    return HttpServer::new(move||{
            App::new()
                    .app_data(state.clone())
                    .wrap(Logger::default())
                    .route("/", web::get().to(index))
                    .route("/api/auth", web::post().to(authenticate))
                    .route("/api/session", web::get().to(session))
                    .route("/api/logout", web::post().to(logout))
                    .route("/api/upload",web::post().to(upload_file))
                    .route("/api/files", web::get().to(list_files)) 
                    .route("/api/download/{filename}", web::get().to(download_file))
        })
        .bind("0.0.0.0:8080")?
        .run()
        .await
}
