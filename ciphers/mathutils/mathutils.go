package mathutils

import (
	"fmt"
	"math"
)

func IsPrime(numberA int) bool {
	if numberA < 2 {
		return false
	}

	for i := 2; i <= int(math.Sqrt(float64(numberA))); i++ {
		if numberA%i == 0 {
			return false
		}
	}

	return true
}

func GCD(numberA int, numberB int) int {
	for numberB > 0 {
		numberA, numberB = numberB, numberA%numberB
	}

	return numberA
}

func ExtendedGCD(numberA int, numberB int) (int, int, int) {
	remainder, nextRemainder := numberA, numberB
	x, nextX := 1, 0
	y, nextY := 0, 1

	for nextRemainder != 0 {
		quotient := remainder / nextRemainder

		remainder, nextRemainder = nextRemainder, remainder-quotient*nextRemainder
		x, nextX = nextX, x-quotient*nextX
		y, nextY = nextY, y-quotient*nextY
	}

	return remainder, x, y
}

func Mod(numberA int, modulo int) (int, error) {
	if modulo <= 0 {
		return 0, fmt.Errorf("modulo must be positive, got %d", modulo)
	}

	result := numberA % modulo
	if result < 0 {
		result += modulo
	}

	return result, nil
}

func ModularInverse(numberA int, modulo int) (int, bool, error) {
	gcd, xCoeff, _ := ExtendedGCD(numberA, modulo)
	if gcd != 1 {
		return 0, false, nil
	}

	inverse, err := Mod(xCoeff, modulo)
	if err != nil {
		return 0, false, err
	}

	return inverse, true, nil
}

func MatrixInverseModuloPrime(matrix *Matrix[int], moduloPrime int) (*Matrix[int], error) {
	if moduloPrime <= 0 {
		return nil, fmt.Errorf("modulo must be positive, got %d", moduloPrime)
	}

	if !IsPrime(moduloPrime) {
		return nil, fmt.Errorf("modulo must be prime, got %d", moduloPrime)
	}

	if matrix.Rows() != matrix.Columns() {
		return nil, fmt.Errorf("invalid matrix provided, must be square, got rows = %d columns = %d", matrix.Rows(), matrix.Columns())
	}

	// Create the [A|I] augmented matrix of size Nx2N
	size := matrix.Rows()
	augmentedMatrix, _ := NewMatrixZero[int](size, size*2)
	for i := range size {
		// Fill the [A] part of the matrix
		for j := range size {
			augmentedMatrix.Data[i][j], _ = Mod(matrix.Data[i][j], moduloPrime)
		}

		// Fill the [I] part of the matrix
		for j := range size {
			if i == j {
				augmentedMatrix.Data[i][j+size] = 1
			}
		}
	}

	for k := range size {
		pivotRow := -1
		for row := k; row < size; row++ {
			if GCD(augmentedMatrix.Data[row][k], moduloPrime) == 1 {
				pivotRow = row
				break
			}
		}

		if pivotRow == -1 {
			return nil, fmt.Errorf("the given matrix is not invertible")
		}

		// Swap rows
		if pivotRow != k {
			augmentedMatrix.Data[pivotRow], augmentedMatrix.Data[k] = augmentedMatrix.Data[k], augmentedMatrix.Data[pivotRow]
		}

		pivot, _ := Mod(augmentedMatrix.Data[k][k], moduloPrime)

		// Pivot is coPrime with modulo
		inverse, _, _ := ModularInverse(pivot, moduloPrime)
		// Normalize pivot row
		for i := range 2 * size {
			augmentedMatrix.Data[k][i], _ = Mod(augmentedMatrix.Data[k][i]*inverse, moduloPrime)
		}

		// Eliminate all other rows
		for i := range size {
			if i == k {
				continue
			}

			factor := augmentedMatrix.Data[i][k]
			for j := range 2 * size {
				augmentedMatrix.Data[i][j], _ = Mod(augmentedMatrix.Data[i][j]-factor*augmentedMatrix.Data[k][j], moduloPrime)
			}
		}
	}

	inverseMatrix, _ := NewMatrixZero[int](size, size)
	for i := range size {
		for j := range size {
			inverseMatrix.Data[i][j] = augmentedMatrix.Data[i][j+size]
		}
	}

	return inverseMatrix, nil
}

/*
BinaryExponentiation performs fast exponentiation of number to the given power.
*/
func BinaryExponentiation(number uint64, power uint64) uint64 {
	result := uint64(1)
	for power > 0 {
		if power&1 == 1 {
			result *= number
		}

		number *= number
		power >>= 1
	}

	return result
}
