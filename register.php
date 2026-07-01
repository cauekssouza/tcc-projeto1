<?php
declare(strict_types=1);

// Include config file (garanta que $link seja um mysqli válido e com charset definido)
require_once __DIR__ . "/config.php";

// Define charset da conexão (protege contra problemas de encoding)
if ($link instanceof mysqli) {
    $link->set_charset('utf8mb4');
}

// Inicia sessão (útil para mensagens, CSRF etc.)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Gera token CSRF simples
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Define variáveis e inicializa com valores vazios
$username = $password = $confirm_password = "";
$username_err = $password_err = $confirm_password_err = "";

// Processa dados do formulário quando enviado
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // Verifica token CSRF
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Invalid request.");
    }

    // Sanitiza entrada básica
    $raw_username = isset($_POST["username"]) ? trim($_POST["username"]) : "";
    $raw_password = isset($_POST["password"]) ? $_POST["password"] : "";
    $raw_confirm  = isset($_POST["confirm_password"]) ? $_POST["confirm_password"] : "";

    // Validate username
    if ($raw_username === "") {
        $username_err = "Please enter a username.";
    } elseif (strlen($raw_username) < 3 || strlen($raw_username) > 50) {
        $username_err = "Username must be between 3 and 50 characters.";
    } elseif (!preg_match('/^[a-zA-Z0-9_.-]+$/', $raw_username)) {
        $username_err = "Username may only contain letters, numbers, dots, underscores and hyphens.";
    } else {
        // Prepare a select statement
        $sql = "SELECT id FROM users WHERE username = ?";
        $stmt = mysqli_prepare($link, $sql);
        if ($stmt === false) {
            // Não exibir detalhes de erro ao usuário
            $username_err = "An error occurred. Please try again later.";
        } else {
            $param_username = $raw_username;
            mysqli_stmt_bind_param($stmt, "s", $param_username);

            if (mysqli_stmt_execute($stmt)) {
                mysqli_stmt_store_result($stmt);

                if (mysqli_stmt_num_rows($stmt) === 1) {
                    $username_err = "This username is already taken.";
                } else {
                    $username = $raw_username;
                }
            } else {
                $username_err = "An error occurred. Please try again later.";
            }

            mysqli_stmt_close($stmt);
        }
    }

    // Validate password
    if ($raw_password === "") {
        $password_err = "Please enter a password.";
    } elseif (strlen($raw_password) < 8) {
        $password_err = "Password must have at least 8 characters.";
    } else {
        // Opcional: validar complexidade (maiúscula, minúscula, número, símbolo)
        $password = $raw_password;
    }

    // Validate confirm password
    if ($raw_confirm === "") {
        $confirm_password_err = "Please confirm password.";
    } else {
        $confirm_password = $raw_confirm;
        if ($password_err === "" && $password !== $confirm_password) {
            $confirm_password_err = "Password did not match.";
        }
    }

    // Check input errors before inserting in database
    if ($username_err === "" && $password_err === "" && $confirm_password_err === "") {

        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
        $stmt = mysqli_prepare($link, $sql);

        if ($stmt === false) {
            // Não revelar detalhes de erro
            $password_err = "An error occurred. Please try again later.";
        } else {
            $param_username = $username;
            $param_password = password_hash($password, PASSWORD_DEFAULT);

            mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);

            if (mysqli_stmt_execute($stmt)) {
                // Regenera token CSRF após uso
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                header("Location: login.php");
                exit;
            } else {
                $password_err = "An error occurred. Please try again later.";
            }

            mysqli_stmt_close($stmt);
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
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; margin: 0 auto; margin-top: 40px; }
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
