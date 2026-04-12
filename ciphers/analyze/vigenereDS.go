package analyze

import "sort"

type treeNode struct {
	children  [26]*treeNode
	count     int
	positions []int
}

type tree struct {
	root      *treeNode
	maxHeight int
}

func newTree(maxHeight int) *tree {
	return &tree{
		root:      &treeNode{},
		maxHeight: maxHeight,
	}
}

func (t *tree) insertNgram(ngram []byte, position int) {
	node := t.root
	for i := range len(ngram) {
		index := ngram[i]
		if node.children[index] == nil {
			node.children[index] = &treeNode{}
		}

		node = node.children[index]
		node.count += 1
		node.positions = append(node.positions, position+i)
	}
}

func (t *tree) insertAllNgrams(buffer []byte) {
	length := len(buffer)
	maxLength := t.maxHeight
	for start := range length {
		end := min(start+maxLength, length)
		t.insertNgram(buffer[start:end], start)
	}
}

type nGramCount struct {
	nGramText string
	count     int
	positions []int
}

func (t *tree) collectNgrams() []nGramCount {
	var results []nGramCount
	buffer := make([]byte, t.maxHeight)

	collectNgramsHelper(t.root, buffer[:], 0, &results)
	filteredResults := make([]nGramCount, 0, len(results))
	for _, result := range results {
		if len(result.nGramText) >= 3 && result.count >= 2 {
			filteredResults = append(filteredResults, result)
		}
	}
	sort.Slice(filteredResults, func(i, j int) bool {
		return filteredResults[i].count > filteredResults[j].count
	})

	return filteredResults
}

func collectNgramsHelper(node *treeNode, buffer []byte, depth int, results *[]nGramCount) {
	if node.count > 0 {
		*results = append(*results, nGramCount{string(buffer[:depth]), node.count, node.positions})
	}

	for i, child := range node.children {
		if child != nil {
			buffer[depth] = 'a' + byte(i)
			collectNgramsHelper(child, buffer, depth+1, results)
		}
	}
}
