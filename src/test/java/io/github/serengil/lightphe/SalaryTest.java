package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_salary.py}. */
class SalaryTest {

    @Test
    @DisplayName("A salary can be raised without ever decrypting it")
    void testApi() {
        LightPHE cs = LightPHE.builder().algorithmName("Paillier").keySize(50).build();

        // set initial base salary to 10000 usd
        long salary = 10000;
        Ciphertext salaryEncrypted = cs.encrypt(salary);

        // add 1000 usd to base salary
        long wageIncrease = 1000;
        Ciphertext increaseEncrypted = cs.encrypt(wageIncrease);

        // perform homomorphic addition
        assertThat(cs.decrypt(salaryEncrypted.add(increaseEncrypted)))
                .isEqualTo(BigInteger.valueOf(salary + wageIncrease));

        // increase base salary by 5%
        double ratio = 1.05;
        assertThat(cs.decrypt(salaryEncrypted.multiply(ratio)))
                .isEqualTo(BigInteger.valueOf(10500));
    }
}
