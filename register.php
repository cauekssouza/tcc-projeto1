<?php
declare(strict_types=1);

// Include config file (garanta que $link seja um mysqli válido)
require_once __DIR__ . '/config.php';

// Inicia sessão (útil para CSRF, mensagens, etc.)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Gera token CSRF se ainda não existir
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Define variáveis e inicializa com valores vazios
$username = $password = $confirm_password = "";
$username_err = $password_err = $confirm_password_err = "";

// Processa dados do formulário quando enviado
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // Verifica token CSRF
    if (
        empty($_POST['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], (string)$_POST['csrf_token'])
    ) {
        die("Invalid request.");
    }

    // Sanitiza entrada básica
    $raw_username = isset($_POST["username"]) ? trim((string)$_POST["username"]) : "";
    $raw_password = isset($_POST["password"]) ? (string)$_POST["password"] : "";
    $raw_confirm  = isset($_POST["confirm_password"]) ? (string)$_POST["confirm_password"] : "";

    // Valida username
    if ($raw_username === "") {
        $username_err = "Please enter a username.";
    } elseif (strlen($raw_username) < 3 || strlen($raw_username) > 50) {
        $username_err = "Username must be between 3 and 50 characters.";
    } elseif (!preg_match('/^[a-zA-Z0-9_.-]+$/', $raw_username)) {
        $username_err = "Username may only contain letters, numbers, dots, underscores and hyphens.";
    } else {
        // Prepara statement de SELECT
        $sql = "SELECT id FROM users WHERE username = ? LIMIT 1";

        if ($stmt = mysqli_prepare($link, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $raw_username);

            if (mysqli_stmt_execute($stmt)) {
                mysqli_stmt_store_result($stmt);

                if (mysqli_stmt_num_rows($stmt) === 1) {
                    $username_err = "This username is already taken.";
                } else {
                    $username = $raw_username;
                }
            } else {
                // Não exponha detalhes de erro ao usuário
                $username_err = "Unable to validate username at the moment.";
            }

            mysqli_stmt_close($stmt);
        } else {
            $username_err = "Internal error. Please try again later.";
        }
    }

    // Valida password
    if (trim($raw_password) === "") {
        $password_err = "Please enter a password.";
    } elseif (strlen($raw_password) < 8) {
        $password_err = "Password must have at least 8 characters.";
    } elseif (!preg_match('/[A-Z]/', $raw_password) ||
              !preg_match('/[a-z]/', $raw_password) ||
              !preg_match('/[0-9]/', $raw_password)) {
        $password_err = "Password must contain upper, lower case letters and numbers.";
    } else {
        $password = $raw_password;
    }

    // Valida confirmação de password
    if (trim($raw_confirm) === "") {
        $confirm_password_err = "Please confirm password.";
    } else {
        $confirm_password = $raw_confirm;
        if ($password_err === "" && $password !== $confirm_password) {
            $confirm_password_err = "Password did not match.";
        }
    }

    // Se não houver erros, insere no banco
    if ($username_err === "" && $password_err === "" && $confirm_password_err === "") {

        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";

        if ($stmt = mysqli_prepare($link, $sql)) {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            mysqli_stmt_bind_param($stmt, "ss", $username, $hashed_password);

            if (mysqli_stmt_execute($stmt)) {
                // Regenera token CSRF após uso
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                // Redireciona para login
                header("Location: login.php");
                exit;
            } else {
                // Mensagem genérica
                $password_err = "Unable to create account at the moment.";
            }

            mysqli_stmt_close($stmt);
        } else {
            $password_err = "Internal error. Please try again later.";
        }
    }

    // Fecha conexão
    mysqli_close($link);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign Up</title>
    <link rel="stylesheet"
          href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Sign Up</h2>
        <p>Please fill this form to create an account.</p>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"], ENT_QUOTES, 'UTF-8'); ?>" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                <label>Username</label>
                <input type="text" name="username" class="form-control"
                       value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>">
                <span class="help-block"><?php echo htmlspecialchars($username_err, ENT_QUOTES, 'UTF-8'); ?></span>
            </div>
            <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <label>Password</label>
                <input type="password" name="password" class="form-control" value="">
                <span class="help-block"><?php echo htmlspecialchars($password_err, ENT_QUOTES, 'UTF-8'); ?></span>
            </div>
            <div class="form-group <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" class="form-control" value="">
                <span class="help-block"><?php echo htmlspecialchars($confirm_password_err, ENT_QUOTES, 'UTF-8'); ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Submit">
                <input type="reset" class="btn btn-default" value="Reset">
            </div>
            <p>Already have an account? <a href="login.php">Login here</a>.</p>
        </form>
    </div>
</body>
</html>
