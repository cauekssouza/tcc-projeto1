<?php
require_once "config.php";

// Inicialização segura
$username = "";
$username_err = $password_err = $confirm_password_err = "";

// Processamento do formulário
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // --- VALIDAR USERNAME ---
    $input_username = trim($_POST["username"] ?? "");

    if ($input_username === "") {
        $username_err = "Por favor, informe um nome de usuário.";
    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $input_username)) {
        // Evita caracteres perigosos e nomes inválidos
        $username_err = "O nome de usuário deve conter apenas letras, números e underscore.";
    } else {
        $sql = "SELECT id FROM users WHERE username = ?";
        $stmt = mysqli_prepare($link, $sql);

        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "s", $input_username);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_store_result($stmt);

            if (mysqli_stmt_num_rows($stmt) > 0) {
                $username_err = "Este nome de usuário já está em uso.";
            } else {
                $username = $input_username;
            }

            mysqli_stmt_close($stmt);
        } else {
            error_log("Erro ao preparar statement: " . mysqli_error($link));
            die("Erro interno. Tente novamente mais tarde.");
        }
    }

    // --- VALIDAR SENHA ---
    $input_password = $_POST["password"] ?? "";

    if ($input_password === "") {
        $password_err = "Por favor, informe uma senha.";
    } elseif (strlen($input_password) < 10) {
        // OWASP recomenda senhas mais longas
        $password_err = "A senha deve ter pelo menos 10 caracteres.";
    } elseif (!preg_match('/[A-Z]/', $input_password) ||
              !preg_match('/[a-z]/', $input_password) ||
              !preg_match('/[0-9]/', $input_password)) {
        $password_err = "A senha deve conter letras maiúsculas, minúsculas e números.";
    }

    // --- VALIDAR CONFIRMAÇÃO ---
    $input_confirm = $_POST["confirm_password"] ?? "";

    if ($input_confirm === "") {
        $confirm_password_err = "Por favor, confirme a senha.";
    } elseif ($input_password !== $input_confirm) {
        $confirm_password_err = "As senhas não coincidem.";
    }

    // --- SE TUDO OK, INSERIR NO BANCO ---
    if ($username_err === "" && $password_err === "" && $confirm_password_err === "") {

        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
        $stmt = mysqli_prepare($link, $sql);

        if ($stmt) {

            // OWASP: usar Argon2id quando disponível
            $hashed_password = password_hash($input_password, PASSWORD_ARGON2ID);

            mysqli_stmt_bind_param($stmt, "ss", $username, $hashed_password);

            if (mysqli_stmt_execute($stmt)) {
                header("Location: login.php");
                exit;
            } else {
                error_log("Erro ao inserir usuário: " . mysqli_error($link));
                die("Erro interno. Tente novamente mais tarde.");
            }

            mysqli_stmt_close($stmt);

        } else {
            error_log("Erro ao preparar statement: " . mysqli_error($link));
            die("Erro interno. Tente novamente mais tarde.");
        }
    }

    mysqli_close($link);
}
?>
