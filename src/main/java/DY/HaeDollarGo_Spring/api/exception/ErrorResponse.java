package DY.HaeDollarGo_Spring.api.exception;

public record ErrorResponse(
        String errorCode,
        String message
) {

}
