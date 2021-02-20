<?php

session_start();

$host = "localhost";
$user = "root";
$password = "root";
$dbname = "activity1";

// Create Connection
$con = mysqli_connect($host,$user,$password,$dbname);

// Check Connection
if(!$con){
	die('Connection failed : '.mysqli_connect_error());
}

echo "Connected Successfully";

$sql = "SELECT id, USERNAME, FIRST_NAME, LAST_NAME, PASSWORD FROM users";
$result = $con->query($sql);

if($result->num_rows > 0 ){
	//output data of each row
	while($row = $result->fetch_assoc()){
		echo "id: " . $row["id"]. "USERNAME: " . $row["USERNAME"]. " - Name: " . $row["FIRST_NAME"]. " " . $row["LAST_NAME"]. "PASSWORD: " . $row["PASSWORD"]. "<br>";
  }
} else {
  echo "0 results";
}
$conn->close();
?>