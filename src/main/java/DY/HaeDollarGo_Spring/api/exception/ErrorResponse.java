package DY.HaeDollarGo_Spring.api.exception;

public record ErrorResponse(
        String code,
        String message
) {

}
