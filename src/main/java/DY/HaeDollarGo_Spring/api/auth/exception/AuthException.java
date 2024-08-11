package DY.HaeDollarGo_Spring.api.auth.exception;


import DY.HaeDollarGo_Spring.api.exception.CustomException;
import DY.HaeDollarGo_Spring.api.exception.ErrorCode;

public class AuthException extends CustomException {

    public AuthException(ErrorCode errorCode) {
        super(httpStatus, errorCode);
    }
}
