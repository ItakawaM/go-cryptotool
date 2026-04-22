package mathutils

import "fmt"

/*
Matrix is a generic 2D matrix with elements of type T.
*/
type Matrix[T any] struct {
	Data [][]T
}

/*
NewMatrixZero creates a new matrix with all elements initialized to the zero value of T.

Returns an error if rows or columns is less than or equal to zero.
*/
func NewMatrixZero[T any](rows int, columns int) (*Matrix[T], error) {
	if rows <= 0 || columns <= 0 {
		return nil, fmt.Errorf("rows and columns must be positive, got rows = %d columns = %d", rows, columns)
	}

	data := make([][]T, rows)
	for i := range rows {
		data[i] = make([]T, columns)
	}

	return &Matrix[T]{
		Data: data,
	}, nil
}

/*
NewMatrixFromData creates a new matrix from a 2D slice.

Returns an error if data is empty, contains empty rows, or has inconsistent row lengths.
*/
func NewMatrixFromData[T any](data [][]T) (*Matrix[T], error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data must not be empty")
	}

	rows := len(data)
	columns := len(data[0])

	if columns == 0 {
		return nil, fmt.Errorf("rows must not be empty")
	}

	for i := 1; i < rows; i++ {
		if len(data[i]) != columns {
			return nil, fmt.Errorf("inconsistent row length: row 0 has %d columns, row %d has %d", columns, i, len(data[i]))
		}
	}

	return &Matrix[T]{
		Data: data,
	}, nil
}

/*
Rows returns the number of rows in the matrix.
*/
func (m *Matrix[T]) Rows() int {
	return len(m.Data)
}

/*
Columns returns the number of columns in the matrix.
*/
func (m *Matrix[T]) Columns() int {
	if len(m.Data) == 0 {
		return 0
	}

	return len(m.Data[0])
}
