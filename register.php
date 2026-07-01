<?php
// Sempre exiba menos detalhes de erro em produção
// ini_set('display_errors', 0);
// error_log para logs internos

require_once "config.php"; // $link deve ser um mysqli válido

// Iniciar sessão (útil para CSRF, mensagens, etc.)
session_start();

// Gera token CSRF (exemplo simples)
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Define variáveis
$username = "";
$username_err = $password_err = $confirm_password_err = "";

// Processa dados do formulário
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // Valida token CSRF
    if (
        empty($_POST['csrf_token']) ||
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
    ) {
        die("Invalid request.");
    }

    // Valida username
    $raw_username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    if (empty($raw_username)) {
        $username_err = "Please enter a username.";
    } elseif (strlen($raw_username) < 3 || strlen($raw_username) > 50) {
        $username_err = "Username must be between 3 and 50 characters.";
    } else {
        $sql = "SELECT id FROM users WHERE username = ?";
        $stmt = mysqli_prepare($link, $sql);
        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "s", $raw_username);

            if (mysqli_stmt_execute($stmt)) {
                mysqli_stmt_store_result($stmt);

                if (mysqli_stmt_num_rows($stmt) === 1) {
                    $username_err = "This username is already taken.";
                } else {
                    $username = $raw_username;
                }
            } else {
                // Log interno, mensagem genérica para o usuário
                $username_err = "Something went wrong. Please try again later.";
            }

            mysqli_stmt_close($stmt);
        } else {
            $username_err = "Something went wrong. Please try again later.";
        }
    }

    // Valida password
    $raw_password = filter_input(INPUT_POST, 'password', FILTER_UNSAFE_RAW);
    if (empty($raw_password)) {
        $password_err = "Please enter a password.";
    } elseif (strlen($raw_password) < 8) {
        $password_err = "Password must have at least 8 characters.";
    } else {
        // Aqui você poderia aplicar regras extras (letras maiúsculas, números, etc.)
    }

    // Valida confirm password
    $raw_confirm = filter_input(INPUT_POST, 'confirm_password', FILTER_UNSAFE_RAW);
    if (empty($raw_confirm)) {
        $confirm_password_err = "Please confirm password.";
    } elseif (empty($password_err) && $raw_password !== $raw_confirm) {
        $confirm_password_err = "Password did not match.";
    }

    // Se não há erros, insere no banco
    if (empty($username_err) && empty($password_err) && empty($confirm_password_err)) {
        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
        $stmt = mysqli_prepare($link, $sql);

        if ($stmt) {
            $hashed_password = password_hash($raw_password, PASSWORD_DEFAULT);

            mysqli_stmt_bind_param($stmt, "ss", $username, $hashed_password);

            if (mysqli_stmt_execute($stmt)) {
                // Evita continuar executando após header
                header("Location: login.php");
                exit;
            } else {
                $password_err = "Something went wrong. Please try again later.";
            }

            mysqli_stmt_close($stmt);
        } else {
            $password_err = "Something went wrong. Please try again later.";
        }
    }

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
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"], ENT_QUOTES, 'UTF-8'); ?>" method="post">
        <input type="hidden" name="csrf_token"
               value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">

        <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
            <label>Username</label>
            <input type="text" name="username" class="form-control"
                   value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>">
            <span class="help-block"><?php echo htmlspecialchars($username_err, ENT_QUOTES, 'UTF-8'); ?></span>
        </div>

        <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
            <label>Password</label>
            <!-- Nunca repopular campo de senha -->
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
