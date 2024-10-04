<?php
session_start();

function checkPasswordStrength($password) {
    $strength = 0;
    $feedback = [];

    if (strlen($password) >= 8) {
        $strength++;
    } else {
        $feedback[] = "Password should be at least 8 characters long.";
    }

    if (preg_match('/[A-Z]/', $password)) {
        $strength++;
    } else {
        $feedback[] = "Include at least one uppercase letter.";
    }

    if (preg_match('/[a-z]/', $password)) {
        $strength++;
    } else {
        $feedback[] = "Include at least one lowercase letter.";
    }

    if (preg_match('/[0-9]/', $password)) {
        $strength++;
    } else {
        $feedback[] = "Include at least one number.";
    }

    if (preg_match('/[^A-Za-z0-9]/', $password)) {
        $strength++;
    } else {
        $feedback[] = "Include at least one special character.";
    }

    return ['strength' => $strength, 'feedback' => $feedback];
}

$error = '';
$success = '';
$passwordFeedback = [];
$passwordStrength = 0;

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    $confirmPassword = $_POST['confirm_password'];

    if (empty($username) || empty($email) || empty($password) || empty($confirmPassword)) {
        $error = "All fields are required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format.";
    } elseif ($password !== $confirmPassword) {
        $error = "Passwords do not match.";
    } else {
        $passwordCheck = checkPasswordStrength($password);
        $passwordStrength = $passwordCheck['strength'];
        $passwordFeedback = $passwordCheck['feedback'];

        if ($passwordStrength < 4) {
            $error = "Password is not strong enough.";
        } else {
            $hashedPassword = password_hash($password, PASSWORD_ARGON2ID);
            $success = "Account created successfully!";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <title>Welcome to Cyber Clinic!</title>
    <link rel="stylesheet" href="style.css"> <!-- Linking the CSS file -->
</head>
<body>
    <div class="container">
        <h1>Welcome to Cyber Clinic!</h1>
        <?php if ($error): ?>
            <div class="error"><?php echo $error; ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="success"><?php echo $success; ?></div>
        <?php endif; ?>
        <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
                <div class="password-strength">
                    <div class="strength-meter" style="width: <?php echo $passwordStrength * 20; ?>%"></div>
                </div>
                <?php if (!empty($passwordFeedback)): ?>
                    <ul class="password-feedback">
                        <?php foreach ($passwordFeedback as $feedback): ?>
                            <li><?php echo $feedback; ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>
            <div class="g-recaptcha" data-sitekey="6LcMhVUqAAAAAE3rtaZAoA8Kq1bKD1yC4QwOfbC8"></div>
            <button type="submit" class="submit-button">Sign Up</button>
        </form>
        <div class="login-link">
            <p>Already have an account? <a href="#">Login Here!</a></p>
        </div>
    </div>
    <script>
        function focusField(fieldId) {
            document.getElementById(fieldId).focus();
        }

        document.getElementById('password').addEventListener('input', function() {
            fetch('<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'password=' + encodeURIComponent(this.value)
            })
            .then(response => response.text())
            .then(html => {
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const strengthMeter = doc.querySelector('.strength-meter');
                const passwordFeedback = doc.querySelector('.password-feedback');
                
                if (strengthMeter) {
                    document.querySelector('.strength-meter').style.width = strengthMeter.style.width;
                }
                if (passwordFeedback) {
                    document.querySelector('.password-feedback').innerHTML = passwordFeedback.innerHTML;
                }
            });
        });
    </script>
</body>
</html>