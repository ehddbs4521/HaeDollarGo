package DY.HaeDollarGo_Spring.api.util;

import java.util.UUID;

public class RandomCreater {

    public static String generateKey() {
        return UUID.randomUUID().toString().replace("-", "");
    }

}
