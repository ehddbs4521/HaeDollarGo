package DY.HaeDollarGo_Spring.api.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public abstract class CustomException extends RuntimeException {

    private final HttpStatus httpStatus;
    private final String code;
    private final String message;

    public CustomException(HttpStatus httpStatus, ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.httpStatus = httpStatus;
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
    }

    public CustomException(HttpStatus httpStatus, ErrorCode errorCode, String message) {
        super(message);
        this.httpStatus = httpStatus;
        this.code = errorCode.getCode();
        this.message = message;
    }
}
