[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>OTP SMS
	</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2/dist/tailwind.min.css" type="text/css"></head>
<body>

  
	
	
	
	
	
  
  
	<div class="h-screen bg-gray-500 py-20 px-3">
	  <div class="container mx-auto">
		<div class="max-w-sm mx-auto md:max-w-lg">
		  <div class="w-full">
			<div class="bg-white h-80 py-4 rounded text-center">
			  <form method="post" class="my-8">
				<h1 class="text-2xl font-bold">OTP Verification
				</h1>
				<div class="flex flex-col mt-4">
				  [#if errorMessage??]
				  <div role="alert" class="p-4 mb-4 text-sm text-red-800 rounded-lg bg-red-50 dark:bg-gray-800 dark:text-red-400">
					<span class="font-medium">Danger alert!</span>${errorMessage}
				  </div>
				  [/#if]
				  [#if maskedPhone??]
				  <span>Enter the OTP you received at</span>
				  <span class="font-bold">${maskedPhone}</span>
				  [/#if]
				</div>
				<div id="otp" class="flex flex-row justify-center text-center px-2 mt-5">
				  <input type="number" id="first" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				  <input type="number" id="second" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				  <input type="number" id="third" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				  <input type="number" id="fourth" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				  <input type="number" id="fifth" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				  <input type="number" id="sixth" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				</div>
				<div class="flex flex-row justify-center text-center px-2 mt-5">
				  <div class="flex flex-row justify-center text-center px-2">
					<button type="button" class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-full"> Submit Code</button>
				  </div>
				  <div class="flex flex-row items-center justify-center text-center text-sm font-medium space-x-1 text-green-500">
					<p>Didn't recieve code?
					</p>
					<a href="http://" target="_blank" rel="noopener noreferrer" class="flex flex-row items-center text-blue-600">Resend</a>
				  </div>
				</div>
			  </form>
			</div>
		  </div>
		</div>
	  </div>
	</div>
  
  
</body>

<script>
	window.onload = function () {
	  var form = document.querySelector("form");
	  form.onsubmit = handleFormValidation;
	};
	function handleFormValidation() {
	  var username = document.getElementById('username').value
	  if (username === '') {
		alert('Username is required')
		return false
	  }
	  var password = document.getElementById('password').value
	  if (password === '') {
		alert('Password is required')
		return false
	  }
	  return true
	}
  </script>
</html>