<?php
require_once "config.php";

// Inicialização segura
$username = "";
$username_err = $password_err = $confirm_password_err = "";

// Processamento do formulário
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // Sanitização de entrada
    $input_username = filter_input(INPUT_POST, "username", FILTER_SANITIZE_STRING);
    $input_password = $_POST["password"] ?? "";
    $input_confirm  = $_POST["confirm_password"] ?? "";

    // Validação de username
    if (empty($input_username)) {
        $username_err = "Por favor, informe um nome de usuário.";
    } else {
        $sql = "SELECT id FROM users WHERE username = ?";
        $stmt = mysqli_prepare($link, $sql);

        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "s", $input_username);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_store_result($stmt);

            if (mysqli_stmt_num_rows($stmt) === 1) {
                $username_err = "Este nome de usuário já está em uso.";
            } else {
                $username = $input_username;
            }

            mysqli_stmt_close($stmt);
        }
    }

    // Validação de senha
    if (empty($input_password)) {
        $password_err = "Por favor, informe uma senha.";
    } elseif (strlen($input_password) < 12) {
        // OWASP recomenda mínimo de 12 caracteres
        $password_err = "A senha deve ter pelo menos 12 caracteres.";
    } else {
        // Não armazenar senhas em variáveis exibidas no HTML
        $password = $input_password;
    }

    // Confirmar senha
    if (empty($input_confirm)) {
        $confirm_password_err = "Por favor, confirme a senha.";
    } elseif ($input_password !== $input_confirm) {
        $confirm_password_err = "As senhas não coincidem.";
    }

    // Se tudo estiver válido, inserir no banco
    if (empty($username_err) && empty($password_err) && empty($confirm_password_err)) {

        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
        $stmt = mysqli_prepare($link, $sql);

        if ($stmt) {
            // Hash seguro (bcrypt) — OWASP recomenda PASSWORD_DEFAULT
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            mysqli_stmt_bind_param($stmt, "ss", $username, $hashed_password);

            if (mysqli_stmt_execute($stmt)) {
                header("Location: login.php");
                exit;
            } else {
                error_log("Erro ao inserir usuário: " . mysqli_error($link));
                echo "Ocorreu um erro. Tente novamente mais tarde.";
            }

            mysqli_stmt_close($stmt);
        }
    }

    mysqli_close($link);
}
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Cadastro</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
    <style>
        body { font: 14px sans-serif; }
        .wrapper { width: 350px; padding: 20px; }
    </style>
</head>
<body>
<div class="wrapper">
    <h2>Cadastro</h2>
    <p>Preencha o formulário para criar sua conta.</p>

    <form action="<?= htmlspecialchars($_SERVER["PHP_SELF"]) ?>" method="post">

        <div class="form-group <?= !empty($username_err) ? 'has-error' : '' ?>">
            <label>Usuário</label>
            <input type="text" name="username" class="form-control" value="<?= htmlspecialchars($username) ?>">
            <span class="help-block"><?= $username_err ?></span>
        </div>

        <div class="form-group <?= !empty($password_err) ? 'has-error' : '' ?>">
            <label>Senha</label>
            <input type="password" name="password" class="form-control">
            <span class="help-block"><?= $password_err ?></span>
        </div>

        <div class="form-group <?= !empty($confirm_password_err) ? 'has-error' : '' ?>">
            <label>Confirmar Senha</label>
            <input type="password" name="confirm_password" class="form-control">
            <span class="help-block"><?= $confirm_password_err ?></span>
        </div>

        <div class="form-group">
            <input type="submit" class="btn btn-primary" value="Cadastrar">
            <input type="reset" class="btn btn-default" value="Limpar">
        </div>

        <p>Já possui conta? <a href="login.php">Entrar</a>.</p>
    </form>
</div>
</body>
</html>
