package DY.HaeDollarGo_Spring.api.exception;


import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    // Auth 관련 에러 코드 //
    WRONG_REGISTRATION_ID(BAD_REQUEST,"AE1","해당 소셜은 유의하지 않습니다."),
    SC_FORBIDDEN(FORBIDDEN, "AE2", "권한 없음"),
    UN_AUTHORIZED(UNAUTHORIZED, "AE3", "토큰 검증 실패"),
    FAIL_LOGIN(BAD_REQUEST,"AE4","로그인 실패"),
    INVALID_TOKEN(UNAUTHORIZED,"AE5","유효하지 않은 토큰입니다"),
    INVALID_SIGNATURE(UNAUTHORIZED,"AE6","유효하지 않은 서명입니다"),
    TOKEN_EXPIRED(BAD_REQUEST,"AE7","유효하지 않은 서명입니다"),
    NOT_EXIST_REFRESHTOKEN(NOT_FOUND, "AE8", "존재하지않는 토큰입니다.");


    private final HttpStatus httpStatus;
    private final String code;
    private final String message;
}
