<?php
require_once "config.php";

// Chave secreta para HMAC (idealmente armazenada em variável de ambiente)
define('HMAC_SECRET_KEY', getenv('APP_SECRET_KEY') ?: 'CHAVE_SUPER_SECRETA_ALTERE_ISSO');

function auth($username, $password, $link)
{
    // Consulta segura
    $sql = "SELECT id, username, password FROM users WHERE username = ?";
    
    if ($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $username);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);

        if (mysqli_stmt_num_rows($stmt) == 1) {
            mysqli_stmt_bind_result($stmt, $id, $db_username, $db_password_hash);
            mysqli_stmt_fetch($stmt);

            // Verifica senha usando password_verify (OWASP recomendado)
            if (password_verify($password, $db_password_hash)) {

                // Gera token seguro usando HMAC-SHA256
                $token = hash_hmac(
                    'sha256',
                    $db_username . '|' . time(),
                    HMAC_SECRET_KEY
                );

                // Armazena token na sessão
                $_SESSION['auth_token'] = $token;
                $_SESSION['username'] = $db_username;
                $_SESSION['user_id'] = $id;

                return true;
            }
        }
    }

    return false;
}
?>
