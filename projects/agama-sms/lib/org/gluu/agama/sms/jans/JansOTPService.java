package org.gluu.agama.sms.jans;

import com.twilio.Twilio;
import org.gluu.agama.sms.OTPService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import io.jans.as.common.model.common.User;
import io.jans.as.common.service.common.EncryptionService;
import io.jans.as.common.service.common.UserService;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.as.server.service.AuthenticationService;
import io.jans.agama.engine.service.FlowService;

import java.lang.reflect.Array;
import java.security.SecureRandom;

public class JansOTPService extends OTPService {

    private static final Logger logger = LoggerFactory.getLogger(FlowService.class);
    private static AuthenticationService authenticationService = CdiUtil.bean(AuthenticationService.class);
    private static UserService userService = CdiUtil.bean(UserService.class);
    private static final String OTP_SMS_CODE = "SMSCode";
    private static final String USERNAME = "uid";
    public static final String ACCOUNT_SID = System.getenv("TWILIO_ACCOUNT_SID");
    public static final String AUTH_TOKEN = System.getenv("TWILIO_AUTH_TOKEN");
    public static final PhoneNumber FROM_NUMBER =new com.twilio.type.PhoneNumber(System.getenv("TWILIO_FROM_NUMBER")) ;

    public static final int OTP_CODE_LENGTH = System.getenv("OTP_CODE_LENGTH")!=null? Integer.parseInt(System.getenv("OTP_CODE_LENGTH")) :6;
    @Override
    public boolean validateCreds(String username, String password) {
        logger.info("Validating user credentials {}.", username);
        return authenticationService.authenticate(username, password);
        logger.info("User validation done successfully.");
    }

    @Override
    public String sendOTPCode(String username) {
        try{
            logger.info("Sending OTP Code via SMS to {}.", username);
            String phone = getUserPhoneNumber();
            String maskedPone = maskPhone(phone);
            logger.info("The user {} with number {} and mask {}.", username, phone, maskedPone);
            String otpCode = generateOTpCode(OTP_CODE_LENGTH);
            logger.info("Generated OTP code is {}.", otpCode);
            associateGeneratedCodeToUser(username, otpCode);
            PhoneNumber TO_NUMBER = new com.twilio.type.PhoneNumber(phone);
            Twilio.init(ACCOUNT_SID, AUTH_TOKEN);
            Message sms = Message.creator(TO_NUMBER,FROM_NUMBER, "Here is your OTP Code: "+otpCode).create();
            logger.error("OTP Code has been successfully send to {} at {} .", sms.getTo(), sms.getDateSent());
            return maskedPone;
        }catch (Exception exception){
            logger.error("Error occur while sending  OTP Code via SMS to {} .", username);
            logger.error("Error: {} .", exception.getMessage());
            return null;
        }
    }

    @Override
    public boolean validateOTPCode(String username, String code) {
        try{
            logger.info("Validating OTP Code {} .", code);
            return true;
        }catch (Exception exception){
            logger.info("OTP Code {} is valid for the associated user.", code);
            logger.error("Error: {} .", exception.getMessage());
            return false;
        }
    }

    private String generateOTpCode(int codeLength){
        String numbers = "0123456789";
        SecureRandom random = new SecureRandom();
        char[] otp = new char[codeLength];
        for (int i = 0; i < codeLength; i++) {
            otp[i] = numbers.charAt(random.nextInt(numbers.length()));
        }
        return new String(otp);
    }

    private String getUserPhoneNumber(){
        User currentUser = authenticationService.getAuthenticatedUser();
        String phoneNumber = currentUser.getAttribute("mobile");
        if(phoneNumber == null){
            phoneNumber = currentUser.getAttribute("telephoneNumber");
        }
        return phoneNumber;
    }

    private User getUser(String attributeName, String value) {
        return userService.getUserByAttribute(attributeName, value, true);
    }

    private boolean associateGeneratedCodeToUser(String username, String code){
        try{
            logger.info("============One");
            User user = authenticationService.getAuthenticatedUser();
            logger.info("============Two");
            if(user != null){
                logger.info("============Three");
                user.setAttribute(OTP_SMS_CODE, code, true);
                logger.info("============Four");
                userService.updateUser(user);
                logger.info("============Five");
                return true;
            }else{
                logger.warn("No user with "+USERNAME+" {} found in the database .", username);
                return false;
            }
        }catch (Exception exception){
            logger.error("Error associating OTP SMS code to user {} found in the database .", username);
            logger.error("Error: {} .", exception.getMessage());
            return false;
        }
    }

    private String maskPhone(String phone) {
        if(phone == null) {
            return "NULL";
        }
        int maskLength = phone.length() - 6;
        if (maskLength <= 0)
            return phone;
        return phone.substring(0,2)+"x".repeat(maskLength) + phone.substring(phone.length()-3);
    }

}
