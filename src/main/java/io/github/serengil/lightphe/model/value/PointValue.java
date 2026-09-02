package io.github.serengil.lightphe.model.value;

import io.github.serengil.lightphe.ecc.CurvePoint;
import java.math.BigInteger;
import java.util.Objects;

/**
 * An affine point on an elliptic curve, carried without a reference to the curve itself: the owning
 * cryptosystem knows which curve the coordinates belong to.
 *
 * @param x the x coordinate, or {@code null} at infinity
 * @param y the y coordinate, or {@code null} at infinity
 * @param infinity whether this is the point at infinity
 */
public record PointValue(BigInteger x, BigInteger y, boolean infinity) implements CipherValue {

    /**
     * Builds an affine point value.
     *
     * @param x the x coordinate
     * @param y the y coordinate
     * @return the point value
     */
    public static PointValue of(BigInteger x, BigInteger y) {
        return new PointValue(
                Objects.requireNonNull(x, "x"), Objects.requireNonNull(y, "y"), false);
    }

    /**
     * Returns the point at infinity.
     *
     * @return the infinity marker
     */
    public static PointValue atInfinity() {
        return new PointValue(null, null, true);
    }

    /**
     * Captures the coordinates of a curve point.
     *
     * @param point the curve point
     * @return the detached point value
     */
    public static PointValue from(CurvePoint point) {
        return point.isInfinity() ? atInfinity() : of(point.x(), point.y());
    }

    @Override
    public String toString() {
        return infinity ? "𝒪" : "(" + x + ", " + y + ")";
    }
}
