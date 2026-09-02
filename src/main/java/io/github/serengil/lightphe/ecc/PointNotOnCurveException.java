package io.github.serengil.lightphe.ecc;

/**
 * Raised when a pair of coordinates does not satisfy the equation of the curve it is claimed to
 * belong to.
 *
 * <p>Counterpart of {@code lightecc.commons.errors.PointNotOnCurve}, which derives from Python's
 * {@code ValueError}; this class derives from {@link IllegalArgumentException} for the same reason.
 */
public class PointNotOnCurveException extends IllegalArgumentException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message description of the offending point
     */
    public PointNotOnCurveException(String message) {
        super(message);
    }
}
