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

struct AppState {
    auth_tokens: Arc<Mutex<HashMap<String,String>>>,
    encryption_key:Aes256Gcm,
}

async fn index() -> impl Responder{
    HttpResponse::Ok().content_type("text/html").body(r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure File Share</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                .upload-section, .download-section { margin: 20px 0; }
                .file-list { list-style: none; padding: 0; }
                .file-list li { margin: 10px 0; }
            </style>
        </head>
        <body>
            <h1>Secure File Share</h1>
            <div class="auth-section">
                <h2>Login</h2>
                <input type="text" id="username" placeholder="Username">
                <input type="password" id="password" placeholder="Password">
                <button onclick="login()">Login</button>
            </div>
            <div class="upload-section" style="display: none">
                <h2>Upload File</h2>
                <input type="file" id="fileInput" multiple>
                <button onclick="uploadFile()">Upload</button>
            </div>
            <div class="download-section" style="display: none">
                <h2>Available Files</h2>
                <ul class="file-list" id="fileList"></ul>
            </div>
            <script>
                let token = null;
                async function login() {
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    const response = await fetch('/api/auth', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });
                    const data = await response.json();
                    if (data.token) {
                        token = data.token;
                        document.querySelector('.auth-section').style.display = 'none';
                        document.querySelector('.upload-section').style.display = 'block';
                        document.querySelector('.download-section').style.display = 'block';
                        listFiles();
                    }
                }
                async function listFiles() {
                    const response = await fetch('/api/files', {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                    const files = await response.json();
                    const fileList = document.getElementById('fileList');
                    fileList.innerHTML = '';
                    files.forEach(file => {
                        const li = document.createElement('li');
                        li.innerHTML = `<a href="/api/download/${file}" download>${file}</a>`;
                        fileList.appendChild(li);
                    });
                }
                async function uploadFile() {
                    const fileInput = document.getElementById('fileInput');
                    const formData = new FormData();
                    for (const file of fileInput.files) {
                        formData.append('files', file);
                    }
                    await fetch('/api/upload', {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${token}` },
                        body: formData
                    });
                    listFiles();
                }
            </script>
        </body>
        </html>
    "#)
}


async fn authenticate(
    req: web::Json<AuthRequest>,
    state:web::Data<AppState>,
) -> impl Responder{
    if req.username == "admin" && req.password == "password"{

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

async fn upload_file(
    mut payload: Multipart,
    state : web::Data<AppState>,
    req: actix_web::HttpRequest
) -> impl Responder{    
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str(){
            if auth_str.starts_with("Bearer ") {
                let token = auth_str[7..].to_string();
                if state.auth_tokens.lock().unwrap().contains_key(&token){
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
                    return HttpResponse::Ok().json(files_saved);
                    }
                }
            }
        }
    }
    HttpResponse::Unauthorized().finish()
}

async fn list_files(
    state : web::Data<AppState>,
    req:actix_web::HttpRequest
) -> impl Responder{

    if let Some(auth_header) = req.headers().get("Authorization"){
        if let Ok(auth_str) = auth_header.to_str(){
            if auth_str.starts_with("Bearer "){
                let token = auth_str[7..].to_string();
                if state.auth_tokens.lock().unwrap().contains_key(&token){
                    let mut files = Vec::new();
                    let mut entries = fs::read_dir("uploads").await.unwrap();
                    while let Some(entry) = entries.next_entry().await.unwrap(){
                        if let Some(file_name) = entry.file_name().to_str(){
                            files.push(file_name.to_string());
                        }
                    }
                    return HttpResponse::Ok().json(files)
                }

            }
        }
    }
    HttpResponse::Unauthorized().finish()
}


async fn download_file(
    path:web::Path<String>,
    state : web::Data<AppState>,
    req : actix_web::HttpRequest
) -> impl Responder{

    if let Some(auth_header) = req.headers().get("Authorization"){
        if let Ok(auth_srt) = auth_header.to_str(){
            if auth_srt.starts_with("Bearer "){
                let token = auth_srt[7..].to_string();
                if state.auth_tokens.lock().unwrap().contains_key(&token){
                    let file_name = path.as_str();
                    let file_path = format!("uploads/{}",file_name);
                    if Path::new(&file_path).exists(){
                        let encrypted_data = fs::read(&file_path).await.unwrap();
                        if encrypted_data.len() <12 {
                            return HttpResponse::InternalServerError().finish();
                        }
                        let (nonce_bytes,ciphertext) = encrypted_data.split_at(12);
                        let nonce = Nonce::from_slice(nonce_bytes);

                        match state.encryption_key.decrypt(nonce, ciphertext){
                            Ok(decrypted_data) => {
                                HttpResponse::Ok()
                                .content_type("application/octet-stram")
                                .append_header((
                                    "Content-Disposition",
                                    format!("attachment; filename=\"{}\"",file_name),
                                
                                )).body(decrypted_data)
                            }
                            Err(_) => HttpResponse::InternalServerError().body("Decryption Failed"),
                        }
                    }else{
                        HttpResponse::NotFound().body("File Not Found")
                    }

                }else {
                    HttpResponse::Unauthorized().finish()
                }
            }else {
                    HttpResponse::Unauthorized().finish()
            }
        }else {
                    HttpResponse::Unauthorized().finish()
        }
    }else {
                    HttpResponse::Unauthorized().finish()
    }

}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    fs::create_dir_all("uploads").await;
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
                    .route("/api/upload",web::post().to(upload_file))
                    .route("/api/files", web::get().to(list_files)) 
                    .route("/api/download/{filename}", web::get().to(download_file))
        })
        .bind("0.0.0.0:8080")?
        .run()
        .await
}