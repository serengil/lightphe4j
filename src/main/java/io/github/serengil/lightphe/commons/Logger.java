package io.github.serengil.lightphe.commons;

import org.slf4j.LoggerFactory;

/**
 * Thin logging facade mirroring {@code lightphe.commons.logger.Logger}.
 *
 * <p>Messages are emitted through SLF4J, so the host application decides where they end up. In
 * addition, the {@code LIGHTPHE_LOG_LEVEL} environment variable acts as a floor exactly as it does
 * in the Python library: it carries a numeric level following Python's {@code logging} module
 * (DEBUG 10, INFO 20, WARNING 30, ERROR 40, CRITICAL 50) and defaults to INFO. Anything below the
 * configured level is dropped before it reaches SLF4J.
 */
public final class Logger {

    /** Python {@code logging.DEBUG}. */
    public static final int DEBUG = 10;

    /** Python {@code logging.INFO}. */
    public static final int INFO = 20;

    /** Python {@code logging.WARNING}. */
    public static final int WARNING = 30;

    /** Python {@code logging.ERROR}. */
    public static final int ERROR = 40;

    /** Python {@code logging.CRITICAL}. */
    public static final int CRITICAL = 50;

    private static final String ENV_VARIABLE = "LIGHTPHE_LOG_LEVEL";

    private final org.slf4j.Logger delegate;
    private final int logLevel;

    private Logger(String module) {
        this.delegate = LoggerFactory.getLogger(module);
        this.logLevel = resolveLogLevel(delegate);
    }

    /**
     * Creates a logger for the given module.
     *
     * @param module the owning class
     * @return a logger bound to that class
     */
    public static Logger forModule(Class<?> module) {
        return new Logger(module.getName());
    }

    /**
     * Creates a logger for the given module name.
     *
     * @param module the module name
     * @return a logger bound to that name
     */
    public static Logger forModule(String module) {
        return new Logger(module);
    }

    private static int resolveLogLevel(org.slf4j.Logger delegate) {
        String raw = System.getenv(ENV_VARIABLE);
        if (raw == null || raw.isBlank()) {
            return INFO;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException err) {
            delegate.info(
                    "Exception while parsing ${}. Expected int but it is {} ({})",
                    ENV_VARIABLE,
                    raw,
                    err.getMessage());
            return INFO;
        }
    }

    /**
     * Returns the effective numeric log level.
     *
     * @return the level resolved from {@code LIGHTPHE_LOG_LEVEL}, or {@link #INFO}
     */
    public int logLevel() {
        return logLevel;
    }

    /**
     * Logs a message at INFO level.
     *
     * @param message the message
     */
    public void info(String message) {
        if (logLevel <= INFO) {
            delegate.info(message);
        }
    }

    /**
     * Logs a lazily built message at DEBUG level. The supplier runs only when the message is
     * actually emitted, which keeps costly string building off the hot path.
     *
     * @param message supplier of the message
     */
    public void debug(java.util.function.Supplier<String> message) {
        if (logLevel <= DEBUG && delegate.isDebugEnabled()) {
            delegate.debug("🕷️ {}", message.get());
        }
    }

    /**
     * Logs a message at DEBUG level.
     *
     * @param message the message
     */
    public void debug(String message) {
        if (logLevel <= DEBUG) {
            delegate.debug("🕷️ {}", message);
        }
    }

    /**
     * Logs a message at WARNING level.
     *
     * @param message the message
     */
    public void warn(String message) {
        if (logLevel <= WARNING) {
            delegate.warn("⚠️ {}", message);
        }
    }

    /**
     * Logs a message at ERROR level.
     *
     * @param message the message
     */
    public void error(String message) {
        if (logLevel <= ERROR) {
            delegate.error("🔴 {}", message);
        }
    }

    /**
     * Logs a message at CRITICAL level, which SLF4J reports as ERROR.
     *
     * @param message the message
     */
    public void critical(String message) {
        if (logLevel <= CRITICAL) {
            delegate.error("💥 {}", message);
        }
    }
}
