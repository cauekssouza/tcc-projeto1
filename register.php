<?php
declare(strict_types=1);

// Include config file
require_once __DIR__ . "/config.php";

// Inicia sessão (útil para CSRF, mensagens, etc.)
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Define variables and initialize with empty values
$username = "";
$password = "";
$confirm_password = "";

$username_err = "";
$password_err = "";
$confirm_password_err = "";

// Processing form data when form is submitted
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // Sanitiza entrada
    $raw_username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $raw_password = filter_input(INPUT_POST, 'password', FILTER_UNSAFE_RAW);
    $raw_confirm_password = filter_input(INPUT_POST, 'confirm_password', FILTER_UNSAFE_RAW);

    // Validate username
    if (empty($raw_username)) {
        $username_err = "Please enter a username.";
    } elseif (strlen($raw_username) < 3 || strlen($raw_username) > 50) {
        $username_err = "Username must be between 3 and 50 characters.";
    } else {
        // Prepare a select statement
        $sql = "SELECT id FROM users WHERE username = ? LIMIT 1";

        $stmt = mysqli_prepare($link, $sql);
        if ($stmt === false) {
            // Logar erro internamente, não exibir detalhes ao usuário
            $username_err = "Oops! Something went wrong. Please try again later.";
        } else {
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $raw_username);

            // Attempt to execute the prepared statement
            if (mysqli_stmt_execute($stmt)) {
                mysqli_stmt_store_result($stmt);

                if (mysqli_stmt_num_rows($stmt) === 1) {
                    $username_err = "This username is already taken.";
                } else {
                    $username = $raw_username;
                }
            } else {
                $username_err = "Oops! Something went wrong. Please try again later.";
            }

            mysqli_stmt_close($stmt);
        }
    }

    // Validate password
    if (empty($raw_password)) {
        $password_err = "Please enter a password.";
    } elseif (strlen($raw_password) < 8) {
        $password_err = "Password must have at least 8 characters.";
    } else {
        // Pode adicionar regras de complexidade aqui (números, letras, símbolos, etc.)
        $password = $raw_password;
    }

    // Validate confirm password
    if (empty($raw_confirm_password)) {
        $confirm_password_err = "Please confirm password.";
    } else {
        $confirm_password = $raw_confirm_password;
        if (empty($password_err) && $password !== $confirm_password) {
            $confirm_password_err = "Password did not match.";
        }
    }

    // Check input errors before inserting in database
    if (empty($username_err) && empty($password_err) && empty($confirm_password_err)) {

        // Prepare an insert statement
        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";

        $stmt = mysqli_prepare($link, $sql);
        if ($stmt === false) {
            // Não expor detalhes de erro
            $password_err = "Something went wrong. Please try again later.";
        } else {
            // Bind variables to the prepared statement as parameters
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            mysqli_stmt_bind_param($stmt, "ss", $username, $hashed_password);

            // Attempt to execute the prepared statement
            if (mysqli_stmt_execute($stmt)) {
                // Regenera ID de sessão por segurança após cadastro
                session_regenerate_id(true);
                header("Location: login.php");
                exit;
            } else {
                $password_err = "Something went wrong. Please try again later.";
            }

            mysqli_stmt_close($stmt);
        }
    }

    // Close connection
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
            <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                <label>Username</label>
                <input type="text" name="username" class="form-control"
                       value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>">
                <span class="help-block"><?php echo htmlspecialchars($username_err, ENT_QUOTES, 'UTF-8'); ?></span>
            </div>
            <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <label>Password</label>
                <!-- Nunca reexibir a senha digitada -->
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
