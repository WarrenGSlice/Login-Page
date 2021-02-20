<?php
// Include config file
require_once "config.php";
 
// Define variables and initialize with empty values
$username = $USER_ROLE = $FIRST_NAME = $LAST_NAME = $ADDRESS = $CITY = $STATE = $ZIP = $COUNTRY = $EMAIL = $password = $confirm_password = "";
$username_err = $email_err = $password_err = $confirm_password_err = "";
$isValid = true;
 
// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
    
    //Pre POST userdate to SQL commands
    $USER_ROLE      =trim($_POST['USER_ROLE']);
    $FIRST_NAME     =trim($_POST['FIRST_NAME']);
    $LAST_NAME      =trim($_POST['LAST_NAME']);
    $ADDRESS        =trim($_POST['ADDRESS']);
    $CITY           =trim($_POST['CITY']);
    $STATE          =trim($_POST['STATE']);
    $ZIP            =trim($_POST['ZIP']);
    $COUNTRY        =trim($_POST['COUNTRY']);

    // Validate username
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter a username.";
    } else{
        // Prepare a select statement
        $sql = "SELECT id FROM users WHERE username = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            
            // Set parameters
            $param_username = trim($_POST["username"]);
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                /* store result */
                mysqli_stmt_store_result($stmt);
                
                if(mysqli_stmt_num_rows($stmt) == 1){
                    $username_err = "This username is already taken.";
                } else{
                    $username = trim($_POST["username"]);
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }
    
    // Validate password
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter a password.";     
    } elseif(strlen(trim($_POST["password"])) < 6){
        $password_err = "Password must have atleast 6 characters.";
    } else{
        $password = trim($_POST["password"]);
    }
    
    //Check if Email already exist
    if(empty(trim($_POST["EMAIL"]))){
        $email_err = "Please enter your email address.";
    } else{
        // Prepare a select statement
        $sql = "SELECT id FROM users WHERE EMAIL = ?";
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_email);
            // Set parameters
            $param_email = trim($_POST["EMAIL"]);
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                /* store result */
                mysqli_stmt_store_result($stmt);
                if(mysqli_stmt_num_rows($stmt) == 1){
                    $email_err = "This email is already registered.";
                } else{
                    $EMAIL = trim($_POST["EMAIL"]);
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }
            // Close statement
            mysqli_stmt_close($stmt);
        }
    }

    //Check if Email is Valid
    if($isValid && !(filter_var($EMAIL,FILTER_VALIDATE_EMAIL))){
        $isValid = false;
        $email_err = "Invalid Email-ID";
      }

    // Validate confirm password
    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "Please confirm password.";     
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "Password did not match.";
        }
    }
    
    // Check input errors before inserting in database
    if(empty($username_err) && empty($email_err) && empty($password_err) && empty($confirm_password_err)){
        
        // Prepare an insert statement
        $sql = "INSERT INTO users (username, USER_ROLE, FIRST_NAME, LAST_NAME, ADDRESS, CITY, STATE, ZIP, COUNTRY, EMAIL, password) VALUES (?,?,?,?,?,?,?,?,?,?,?)";
         
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "sssssssssss", $param_username, $param_user_role, $param_firstName, $param_lastName, $param_address, $param_city, $param_state, $param_zip, $param_country, $param_email, $param_password);
            
            // Set parameters
            $param_username = $username;
            $param_user_role = $USER_ROLE;
            $param_firstName = $FIRST_NAME;
            $param_lastName = $LAST_NAME;
            $param_address = $ADDRESS;
            $param_city = $CITY;
            $param_state = $STATE;
            $param_zip = $ZIP;
            $param_country = $COUNTRY;
            $param_email = $EMAIL;
            $param_password = password_hash($password, PASSWORD_DEFAULT); // Creates a password hash
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Redirect to login page
                header("location: login.php");
            } else{
                echo "Something went wrong. Please try again later.";
            }
            // Close statement
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
    <title>Registration Form</title>
    <link rel="stylesheet" href="form.css" type="text/css">
</head>
<body>
    <div class="container">

        <form id="contact" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
          <h3>User Registration</h3>
          <h4>Please fill this form to create an account.</h4>
            <fieldset class="form-group <?php echo (!empty($username_err)) ? 'has-error' : ''; ?>">
                <input placeholder="UserName" type="text" tabindex="1" name="username" class="form-control" value="<?php echo $username; ?>" autofocus>
                <span class="help-block"><?php echo $username_err; ?></span>
            </fieldset>
            <fieldset class="form-group">
                <input placeholder="User Role" type="text" tabindex="2" name="USER_ROLE" class="form-control" value="<?php echo $USER_ROLE; ?>">
                <span class="help-block"><?php ?></span>
            </fieldset>
            <fieldset class="form-group">
                <input placeholder="First Name" type="text" tabindex="3" name="FIRST_NAME" class="form-control" value="<?php echo $FIRST_NAME; ?>" id="FIRST_NAME" >
                <span class="error"><?= $FIRST_NAME_Err ?></span>
            </fieldset>    
            <fieldset class="form-group">
                <input placeholder="Last Name" type="text" tabindex="4" name="LAST_NAME" class="form-control" value="<?php echo $LAST_NAME; ?>" id="LAST_NAME" >
                <span class="error"><?= $LAST_NAME_Err ?></span>
            </fieldset>
            <fieldset class="form-group">
                <input placeholder="Street Address" type="text" tabindex="5" name="ADDRESS" class="form-control" value="<?php echo $ADDRESS; ?>">
                <span class="help-block"><?php ?></span>
            </fieldset>
            <fieldset class="form-group">
                <input placeholder="City" type="text" tabindex="6" name="CITY" class="form-control" value="<?php echo $CITY; ?>">
                <span class="help-block"><?php ?></span>
            </fieldset>
            <fieldset class="form-group">
                <input placeholder="State" type="text" tabindex="7" name="STATE" class="form-control" value="<?php echo $STATE; ?>">
                <span class="help-block"><?php ?></span>
            </fieldset>
            <fieldset class="form-group">
                <input placeholder="Zip Code" type="text" tabindex="8" name="ZIP" class="form-control" value="<?php echo $ZIP; ?>">
                <span class="help-block"><?php ?></span>
            </fieldset>
            <fieldset class="form-group">
                <input placeholder="Country" type="text" tabindex="9" name="COUNTRY" class="form-control" value="<?php echo $COUNTRY; ?>">
                <span class="help-block"><?php ?></span>
            </fieldset>
            <fieldset class="form-group <?php echo (!empty($email_err)) ? 'has-error' : ''; ?>" >
                <input placeholder="Email Address" type="text" tabindex="10" name="EMAIL" class="form-control" value="<?php echo $EMAIL; ?>">
                <span class="help-block"><?php echo $email_err; ?></span>
            </fieldset>
            <fieldset class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <input placeholder="Password" type="text" tabindex="11" name="password" class="form-control" value="<?php echo $password; ?>">
                <span class="help-block"><?php echo $password_err; ?></span>
            </fieldset>
            <fieldset class="form-group <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
                <input placeholder="Confirm Password" tabindex="12" type="text" name="confirm_password" class="form-control" value="<?php echo $confirm_password; ?>">
                <span class="help-block"><?php echo $confirm_password_err; ?></span>
            </fieldset>
            <fieldset class="form-group">
                <input type="submit" class="btn btn-primary" value="Submit">
                <input type="reset" class="btn btn-default" value="Reset">
            </fieldset>
            <p>Already have an account? <a href="login.php">Login here</a>.</p>
            <p>Go Back to Main Menu <a href="index.html">Main Menu</a></p>
        </form>
    </div>    
</body>
</html>