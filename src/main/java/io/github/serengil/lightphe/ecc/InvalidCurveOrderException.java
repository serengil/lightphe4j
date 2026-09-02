package io.github.serengil.lightphe.ecc;

/**
 * Raised when the declared order {@code n} of a curve does not annihilate its base point, i.e.
 * {@code n * G} is not the identity element.
 *
 * <p>Counterpart of {@code lightecc.commons.errors.InvalidCurveOrder}.
 */
public class InvalidCurveOrderException extends IllegalArgumentException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message description of the invalid order
     */
    public InvalidCurveOrderException(String message) {
        super(message);
    }
}
