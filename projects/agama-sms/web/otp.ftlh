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
			<div class="bg-white h-full py-4 rounded text-center">
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
				  <input type="number" id="1" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				  <input type="number" id="2" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				  <input type="number" id="3" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				  <input type="number" id="4" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				  <input type="number" id="5" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				  <input type="number" id="6" maxlength="1" class="m-2 border h-10 w-10 text-center form-control rounded">
				</div>
				<div class="flex flex-row justify-center text-center px-2 mt-5">
				  <input type="text" id="userCode" maxlength="1" class="m-2 border hidden h-10 w-10 text-center form-control rounded">
				  <div class="flex flex-row justify-center text-center px-2">
					<button type="submit" class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-full"> Submit Code</button>
				  </div>
				</div>
				<div class="flex flex-row justify-center text-center px-2 mt-5">
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
	  var userCode=""
	  var codeFields = document.querySelectorAll('input[type="number"]')
	  for (let i = 0; i < codeFields.length; i++) {
		console.log(codeFields[i].value)
		userCode = userCode.concat(codeFields[i].value)
	  }
	  if (userCode === '' || userCode.length !==6) {
		alert("Please provide the code.")
		return false
	  }
	  else{
		console.log(userCode)
		document.querySelectorAll('input[type="text"]').value = userCode
	  }
	  return true
	}
  </script>
</html>