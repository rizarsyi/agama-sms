package org.gluu.agama.sms;

import org.gluu.agama.sms.jans.JansOTPService;

public abstract class OTPService {

    public abstract boolean validateCreds(String username, String password);

    public abstract boolean sendOTPCode(String username, String userPhoneNumber);

    public abstract boolean validateOTPCode(String username, String code);

    public static OTPService getInstance(){
        return  new JansOTPService();
    }
}
