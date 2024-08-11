package DY.HaeDollarGo_Spring.api.auth.exception;


import DY.HaeDollarGo_Spring.api.exception.CustomException;
import DY.HaeDollarGo_Spring.api.exception.ErrorCode;

public class TokenException extends CustomException {

    public TokenException(ErrorCode errorCode) {
        super(errorCode);
    }
}
