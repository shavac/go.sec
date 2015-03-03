package mem

import "sort"

//import "fmt"

var visited sort.IntSlice
var found bool

func DFS(g map[int]sort.IntSlice, rootId int, f func(int) bool) {
	if found {
		return
	}
	if idx := visited.Search(rootId); idx < len(visited) && visited[idx] == rootId {
		return
	} else {
		visited = append(visited, rootId)
		visited.Sort()
	}
	if f(rootId) {
		found = true
		return
	}
	for _, id := range g[rootId] {
		DFS(g, id, f)
	}
	return
}
