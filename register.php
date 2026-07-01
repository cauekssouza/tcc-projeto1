<?php
declare(strict_types=1);

// Include config file
require_once "config.php";

// Define variables and initialize with empty values
$username = "";
$password = "";
$confirm_password = "";
$username_err = "";
$password_err = "";
$confirm_password_err = "";

// Opcional: variáveis de feedback, preservadas se já existirem em outro trecho
$success = $success ?? null;
$error   = $error ?? null;

// Escolha segura de algoritmo conforme OWASP
$hashAlgo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;

// Processing form data when form is submitted
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // Validate username
    if (empty(trim((string)$_POST["username"]))) {
        $username_err = "Please enter a username.";
    } else {
        // Prepare a select statement
        $sql = "SELECT id FROM users WHERE username = ?";

        if ($stmt = mysqli_prepare($link, $sql)) {
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_username);

            // Set parameters
            $param_username = trim((string)$_POST["username"]);

            // Attempt to execute the prepared statement
            if (mysqli_stmt_execute($stmt)) {
                /* store result */
                mysqli_stmt_store_result($stmt);

                if (mysqli_stmt_num_rows($stmt) === 1) {
                    $username_err = "This username is already taken.";
                } else {
                    $username = $param_username;
                }
            } else {
                $error = "Oops! Something went wrong. Please try again later.";
            }
        }

        // Close statement
        if (isset($stmt)) {
            mysqli_stmt_close($stmt);
        }
    }

    // Validate password
    if (empty(trim((string)$_POST["password"]))) {
        $password_err = "Please enter a password.";
    } elseif (strlen(trim((string)$_POST["password"])) < 6) {
        $password_err = "Password must have atleast 6 characters.";
    } else {
        // Mantém em memória apenas para validação e hash, sem refletir no HTML
        $password = trim((string)$_POST["password"]);
    }

    // Validate confirm password
    if (empty(trim((string)$_POST["confirm_password"]))) {
        $confirm_password_err = "Please confirm password.";
    } else {
        $confirm_password = trim((string)$_POST["confirm_password"]);
        if (empty($password_err) && ($password !== $confirm_password)) {
            $confirm_password_err = "Password did not match.";
        }
    }

    // Check input errors before inserting in database
    if (empty($username_err) && empty($password_err) && empty($confirm_password_err)) {

        // Prepare an insert statement
        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";

        if ($stmt = mysqli_prepare($link, $sql)) {
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);

            // Set parameters
            $param_username = $username;
            // Hash seguro da senha, sem armazenar texto puro
            $param_password = password_hash($password, $hashAlgo);

            // Attempt to execute the prepared statement
            if (mysqli_stmt_execute($stmt)) {
                $success = "Account created successfully.";
                // Redirect to login page
                header("Location: login.php");
                exit;
            } else {
                $error = "Something went wrong. Please try again later.";
            }
        }

        // Close statement
        if (isset($stmt)) {
            mysqli_stmt_close($stmt);
        }

        // Limpa senha da memória após uso (boa prática)
        $password = "";
        $confirm_password = "";
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
        .wrapper{ width: 350px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Sign Up</h2>
        <p>Please fill this form to create an account.</p>

        <?php if (!empty($success)): ?>
            <div class="alert alert-success">
                <?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($error)): ?>
            <div class="alert alert-danger">
                <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                <label>Username</label>
                <input type="text" name="username" class="form-control" value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>">
                <span class="help-block"><?php echo htmlspecialchars($username_err, ENT_QUOTES, 'UTF-8'); ?></span>
            </div>
            <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <label>Password</label>
                <!-- Não refletir senha em texto limpo -->
                <input type="password" name="password" class="form-control" value="">
                <span class="help-block"><?php echo htmlspecialchars($password_err, ENT_QUOTES, 'UTF-8'); ?></span>
            </div>
            <div class="form-group <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
                <label>Confirm Password</label>
                <!-- Não refletir confirmação em texto limpo -->
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
