
$(document).ready(function(){
	
	$("#form-wizard").formwizard({ 
		formPluginEnabled: true,
		validationEnabled: true,
		focusFirstInput : true,
		disableUIStyles : true,
	
		formOptions :{
			success: function(data){$("#status").fadeTo(500,1,function(){ $(this).html("<span>Form was submitted!</span>").fadeTo(5000, 0); })},
			beforeSubmit: function(data){$("#submitted").html("<span>Form was submitted with ajax. Data sent to the server: " + $.param(data) + "</span>");},
			dataType: 'json',
			resetForm: true
		},
		validationOptions : {
			rules: {
				username: "required",
				password: "required",
				password2: {
					equalTo: "#password"
				},
				email: { required: true, email: true },
				eula: "required"
			},
			messages: {
				username: "Please enter your name or username",
				password: "You must enter the password",
				password2: { equalTo: "Password don't match" },
				email: { required: "Please, enter your email", email: "Correct email format is name@domain.com" },
				eula: "You must accept the eula"
			},
			errorClass: "help-inline",
			errorElement: "span",
			highlight:function(element, errorClass, validClass) {
			$(element).parents('.control-group').addClass('error');
			},
			unhighlight: function(element, errorClass, validClass) {
				$(element).parents('.control-group').removeClass('error');
			}
		}
	});	
});
