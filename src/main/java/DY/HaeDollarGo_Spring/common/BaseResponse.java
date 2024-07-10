package DY.HaeDollarGo_Spring.common;

import DY.HaeDollarGo_Spring.global.ErrorCode;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Data;

import static DY.HaeDollarGo_Spring.global.ErrorCode.SUCCESS;


@Data
@JsonPropertyOrder({"code", "message", "data"})
public class BaseResponse<T> {

    private int code;

    private String message;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private T data;

    // data 있는 경우
    public BaseResponse(T data) {
        this.code = Integer.parseInt(SUCCESS.getCode());
        this.message = SUCCESS.getMessage();
        this.data = data;
    }

    // data 없는 경우
    public BaseResponse(ErrorCode status) {
        this.code = Integer.parseInt(status.getCode());
        this.message = status.getMessage();
    }
}
