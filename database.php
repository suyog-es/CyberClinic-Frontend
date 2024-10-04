<?php
session_start();

// Database connection
$servername = "localhost";  // Usually localhost for phpMyAdmin
$username_db = "root";      // Your MySQL username (default is root)
$password_db = "";          // Your MySQL password (leave empty if no password)
$dbname = "cyber_clinic";   // The database name

// Create connection
$conn = new mysqli($servername, $username_db, $password_db, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

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

            // Prepare and bind SQL statement
            $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $email, $hashedPassword);

            if ($stmt->execute()) {
                $success = "Account created successfully!";
            } else {
                $error = "Error: " . $stmt->error;
            }

            $stmt->close();
        }
    }
}

$conn->close();
?>
