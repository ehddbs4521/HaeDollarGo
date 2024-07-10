package DY.HaeDollarGo_Spring.common;

import DY.HaeDollarGo_Spring.global.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class BaseException extends RuntimeException{

    private ErrorCode errorCode;

}
