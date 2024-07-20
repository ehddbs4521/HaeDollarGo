package DY.HaeDollarGo_Spring.api.exception;

import lombok.Getter;

@Getter
public abstract class CustomException extends RuntimeException {

    private final String code;
    private final String message;

    public CustomException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
    }

    public CustomException(ErrorCode errorCode, String message) {
        super(message);
        this.code = errorCode.getCode();
        this.message = message;
    }
}
