<?php
session_start();
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed");
    }

    // Strip newlines from fields that go into headers to prevent CRLF/header injection
    $name = str_replace(array("\r", "\n"), '', $_POST['name']);
    $email = str_replace(array("\r", "\n"), '', $_POST['email']);
    $subject = str_replace(array("\r", "\n"), '', $_POST['subject']);
    
    // Validate the email format before processing
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "<script>alert('Invalid email address. Please try again.'); window.history.back();</script>";
        exit();
    }

    // Sanitize for safe output in HTML email body
    $name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    $email = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
    $subject = htmlspecialchars($subject, ENT_QUOTES, 'UTF-8');
    $message = htmlspecialchars($_POST['message'], ENT_QUOTES, 'UTF-8');

    $to = "support@psychecare.com"; 
    $headers = "From: " . $email . "\r\n";
    $headers .= "Reply-To: " . $email . "\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";

    $email_body = "<h2>New Contact Message</h2>
                   <p><strong>Name:</strong> {$name}</p>
                   <p><strong>Email:</strong> {$email}</p>
                   <p><strong>Message:</strong><br/>" . nl2br($message) . "</p>";

    if(mail($to, $subject, $email_body, $headers)) {
        echo "<script>alert('Message sent successfully!'); window.location.href='index.html';</script>";
    } else {
        echo "<script>alert('Failed to send message. Please try again.'); window.history.back();</script>";
    }
}
?>
