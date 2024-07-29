package DY.HaeDollarGo_Spring.global.common;

public final class TokenValue {

    public static final String TOKEN_PREFIX = "Bearer ";
    public static final Long ACCESS_TTL = 1000 * 60 * 60 * 2L;
    public static final Long REFRESH_TTL = 1000 * 60 * 60 * 24 * 14L;
    public static final String ACCESS_HEADER = "Authorization-Access";
    public static final String REFRESH_HEADER = "Authorization-Refresh";
}
