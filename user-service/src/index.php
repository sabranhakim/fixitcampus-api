<?php
require 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

header("Content-Type: application/json");

// --- Konfigurasi ---
$db_host = getenv('DB_HOST');
$db_name = getenv('DB_DATABASE');
$db_user = getenv('DB_USERNAME');
$db_pass = getenv('DB_PASSWORD');
$jwt_key = getenv('JWT_SECRET_KEY') ?: 'fallback-secret-key';

// --- Koneksi DB ---
try {
    $mysqli = new mysqli($db_host, $db_user, $db_pass, $db_name);
    if ($mysqli->connect_error) {
        throw new Exception("Koneksi gagal: " . $mysqli->connect_error);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => "Masalah koneksi database: " . $e->getMessage()]);
    exit();
}

// Inisialisasi Tabel
$mysqli->query("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL, role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);");

// --- Fungsi Helper Otentikasi ---
function get_auth_payload($jwt_key) {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? null;
    if (!$authHeader) {
        http_response_code(401);
        echo json_encode(['error' => 'Authorization header not found.']);
        return null;
    }
    $token = str_replace('Bearer ', '', $authHeader);
    try {
        $decoded = JWT::decode($token, new Key($jwt_key, 'HS256'));
        return $decoded->data;
    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid or expired token: ' . $e->getMessage()]);
        return null;
    }
}


// --- Routing ---
$request_method = $_SERVER["REQUEST_METHOD"];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri_parts = explode('/', trim($path, '/'));

switch ($uri_parts[0]) {
    case 'register':
        if ($request_method === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            if (!isset($data['name']) || !isset($data['email']) || !isset($data['password'])) {
                http_response_code(400);
                echo json_encode(["error" => "Name, email, and password are required"]);
                exit();
            }
            $name = $data['name'];
            $email = $data['email'];
            $password_hash = password_hash($data['password'], PASSWORD_BCRYPT);
            
            // Ambil role dari data, default 'user'. Validasi untuk memastikan hanya 'user' atau 'admin'.
            $role = $data['role'] ?? 'user';
            if (!in_array($role, ['user', 'admin'])) {
                $role = 'user';
            }

            $stmt = $mysqli->prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssss", $name, $email, $password_hash, $role);
            if ($stmt->execute()) {
                http_response_code(201);
                echo json_encode(["message" => "User registered successfully"]);
            } else {
                http_response_code(400);
                echo json_encode(["error" => "Failed to register user. Email might already exist."]);
            }
        }
        break;

    case 'login':
        if ($request_method === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $stmt = $mysqli->prepare("SELECT id, name, email, password, role FROM users WHERE email = ?");
            $stmt->bind_param("s", $data['email']);
            $stmt->execute();
            $user = $stmt->get_result()->fetch_assoc();

            if ($user && password_verify($data['password'], $user['password'])) {
                $payload = [
                    'iat' => time(), 'exp' => time() + (60 * 60 * 8), 'iss' => 'fixitcampus-user-service',
                    'data' => ['user_id' => $user['id'], 'role' => $user['role']]
                ];
                $jwt = JWT::encode($payload, $jwt_key, 'HS256');
                echo json_encode(["message" => "Login successful", "token" => $jwt]);
            } else {
                http_response_code(401);
                echo json_encode(["error" => "Invalid email or password"]);
            }
        }
        break;
    
    case 'users':
        if ($request_method === 'GET') {
            // Semua endpoint di bawah /users memerlukan otentikasi
            $auth_payload = get_auth_payload($jwt_key);
            if ($auth_payload === null) {
                exit(); // Error sudah dikirim oleh get_auth_payload
            }

            // GET /users/{id}
            if (isset($uri_parts[1]) && is_numeric($uri_parts[1])) {
                $user_id_to_get = intval($uri_parts[1]);
                // Admin bisa lihat siapa saja, user biasa hanya bisa lihat diri sendiri
                if ($auth_payload->role !== 'admin' && $auth_payload->user_id !== $user_id_to_get) {
                    http_response_code(403);
                    echo json_encode(['error' => 'Forbidden: You can only view your own profile.']);
                    exit();
                }
                $stmt = $mysqli->prepare("SELECT id, name, email, role FROM users WHERE id = ?");
                $stmt->bind_param("i", $user_id_to_get);
                $stmt->execute();
                $user = $stmt->get_result()->fetch_assoc();
                if ($user) {
                    echo json_encode($user);
                } else {
                    http_response_code(404);
                    echo json_encode(['error' => 'User not found.']);
                }
            } 
            // GET /users
            else {
                // Hanya admin yang bisa melihat semua user
                if ($auth_payload->role !== 'admin') {
                    http_response_code(403);
                    echo json_encode(['error' => 'Forbidden: Admin access required.']);
                    exit();
                }
                $result = $mysqli->query("SELECT id, name, email, role FROM users");
                $users = $result->fetch_all(MYSQLI_ASSOC);
                echo json_encode($users);
            }
        }
        break;

    default:
        http_response_code(404);
        echo json_encode(["error" => "Endpoint not found"]);
        break;
}

$mysqli->close();