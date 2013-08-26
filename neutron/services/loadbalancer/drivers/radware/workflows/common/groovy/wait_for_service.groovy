import com.radware.alteon.beans.adc.*;
import com.radware.alteon.api.*;
import com.radware.alteon.sdk.*
import com.radware.alteon.sdk.rpm.*
import com.radware.alteon.api.impl.AlteonCliUtils;
import com.radware.alteon.cli.CliSession;



service.provision()

//
// temp patch until provision will make sure SSH is active
// sleep up to 5 min

counter = 0
logger.info("Start waiting for SSH connection.")
COUNTER_MAX = 300
SLEEP_TIME = 2000

while (counter < COUNTER_MAX) {
  try {
        validateAdcCLIConnection(service.getPrimary());
        logger.info("Validated primary (" + counter + ")")
        if (service.request.ha) {
            validateAdcCLIConnection(service.getSecondary());
            logger.info("Validated secondary (" + counter + ")")
        }
        break
  } catch (Exception e) {
      counter++
      sleep(SLEEP_TIME)
  }
}

if(counter >= COUNTER_MAX) {
    throw new Exception("Could not validate SSH connection after " + (COUNTER_MAX * SLEEP_TIME) / 1000 + " seconds.")
}

logger.info("Validated SSH connection..")

def validateAdcCLIConnection(AdcCLIConnection connection) {
    CliSession s = new CliSession(AlteonCliUtils.convertConnection(connection));
    try {
        s.connect();
        s.close();
    } catch (Exception e) {
        throw new AdcConnectionException("IOException while validating the connection.  Please check the connection settings.",e);
    }
}

