<?php
require_once "config.php";

// Inicialização segura
$username = "";
$username_err = $password_err = $confirm_password_err = "";

// Processamento do formulário
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // --- Sanitização e validação de entrada ---
    $input_username = filter_input(INPUT_POST, "username", FILTER_SANITIZE_STRING);
    $input_password = $_POST["password"] ?? "";
    $input_confirm  = $_POST["confirm_password"] ?? "";

    // Validação de username
    if (empty($input_username)) {
        $username_err = "Please enter a username.";
    } else {
        $sql = "SELECT id FROM users WHERE username = ?";
        $stmt = mysqli_prepare($link, $sql);

        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "s", $input_username);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_store_result($stmt);

            if (mysqli_stmt_num_rows($stmt) === 1) {
                $username_err = "This username is already taken.";
            } else {
                $username = $input_username;
            }

            mysqli_stmt_close($stmt);
        }
    }

    // Validação de senha
    if (empty($input_password)) {
        $password_err = "Please enter a password.";
    } elseif (strlen($input_password) < 10) {
        // OWASP recomenda mínimo de 10 caracteres
        $password_err = "Password must have at least 10 characters.";
    } else {
        $password = $input_password;
    }

    // Confirmar senha
    if (empty($input_confirm)) {
        $confirm_password_err = "Please confirm password.";
    } elseif ($password !== $input_confirm) {
        $confirm_password_err = "Passwords do not match.";
    }

    // Se não houver erros, inserir no banco
    if (empty($username_err) && empty($password_err) && empty($confirm_password_err)) {

        // Hash seguro (Argon2id recomendado pela OWASP)
        $hashed_password = password_hash(
            $password,
            PASSWORD_ARGON2ID,
            [
                "memory_cost" => 1<<17,   // 128MB
                "time_cost"   => 4,
                "threads"     => 2
            ]
        );

        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
        $stmt = mysqli_prepare($link, $sql);

        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "ss", $username, $hashed_password);

            if (mysqli_stmt_execute($stmt)) {
                header("Location: login.php");
                exit;
            } else {
                error_log("Database insert error: " . mysqli_error($link));
                echo "Something went wrong. Please try again later.";
            }

            mysqli_stmt_close($stmt);
        }
    }

    mysqli_close($link);
}
?>

<input type="password" name="password" class="form-control">



