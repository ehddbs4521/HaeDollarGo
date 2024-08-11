package DY.HaeDollarGo_Spring.api.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(CustomException.class)
    public ResponseEntity<?> handleCustomException(CustomException e) {
        log.info("abc");
        return toResponse(e.getHttpStatus(), e.getCode(), e.getMessage());
    }

    private static ResponseEntity<ErrorResponse> toResponse(HttpStatus httpStatus, String errorCode, String message) {
        return ResponseEntity.status(httpStatus)
                .body(new ErrorResponse(errorCode, message));
    }
}
