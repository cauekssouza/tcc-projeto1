<?php
declare(strict_types=1);

// Carrega configuração segura
require_once "config_secure.php"; // Deve conter PDO com ERRMODE_EXCEPTION

// Inicializa variáveis
$username = "";
$errors = [
    "username" => "",
    "password" => "",
    "confirm"  => ""
];

// Processa envio do formulário
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // Sanitização forte
    $inputUsername = trim($_POST["username"] ?? "");
    $inputPassword = $_POST["password"] ?? "";
    $inputConfirm  = $_POST["confirm_password"] ?? "";

    // Validação de username
    if ($inputUsername === "") {
        $errors["username"] = "Informe um nome de usuário.";
    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $inputUsername)) {
        $errors["username"] = "O nome de usuário deve conter apenas letras, números e _.";
    } else {
        // Verifica se já existe
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = :u LIMIT 1");
        $stmt->execute(["u" => $inputUsername]);

        if ($stmt->fetch()) {
            $errors["username"] = "Este nome de usuário já está em uso.";
        } else {
            $username = $inputUsername;
        }
    }

    // Validação de senha
    if ($inputPassword === "") {
        $errors["password"] = "Informe uma senha.";
    } elseif (strlen($inputPassword) < 10) {
        // Política moderna OWASP: mínimo 10 caracteres
        $errors["password"] = "A senha deve ter pelo menos 10 caracteres.";
    } else {
        // OK
    }

    // Confirmação de senha
    if ($inputConfirm === "") {
        $errors["confirm"] = "Confirme sua senha.";
    } elseif ($inputPassword !== $inputConfirm) {
        $errors["confirm"] = "As senhas não coincidem.";
    }

    // Se não houver erros, insere
    if (!array_filter($errors)) {

        // Hash seguro (bcrypt ou argon2i/argon2id)
        $hash = password_hash($inputPassword, PASSWORD_ARGON2ID);

        try {
            $stmt = $pdo->prepare("
                INSERT INTO users (username, password_hash, created_at)
                VALUES (:u, :p, NOW())
            ");

            $stmt->execute([
                "u" => $username,
                "p" => $hash
            ]);

            // Redireciona
            header("Location: login.php");
            exit;

        } catch (Exception $e) {
            // Log seguro (NUNCA exibir detalhes ao usuário)
            error_log("Erro ao registrar usuário: " . $e->getMessage());
            echo "Ocorreu um erro. Tente novamente.";
        }
    }
}
?>



<form action="<?= htmlspecialchars($_SERVER["PHP_SELF"]) ?>" method="post">
    <div class="form-group <?= $errors["username"] ? 'has-error' : '' ?>">
        <label>Username</label>
        <input type="text" name="username" class="form-control"
               value="<?= htmlspecialchars($username) ?>">
        <span class="help-block"><?= $errors["username"] ?></span>
    </div>

    <div class="form-group <?= $errors["password"] ? 'has-error' : '' ?>">
        <label>Password</label>
        <input type="password" name="password" class="form-control">
        <span class="help-block"><?= $errors["password"] ?></span>
    </div>

    <div class="form-group <?= $errors["confirm"] ? 'has-error' : '' ?>">
        <label>Confirm Password</label>
        <input type="password" name="confirm_password" class="form-control">
        <span class="help-block"><?= $errors["confirm"] ?></span>
    </div>

    <div class="form-group">
        <input type="submit" class="btn btn-primary" value="Submit">
        <input type="reset" class="btn btn-default" value="Reset">
    </div>
</form>
