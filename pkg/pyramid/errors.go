package pyramid

import "errors"

var (
	errPathInWorkspace = errors.New("file cannot be located in the workspace")
	errEmptyDirInPath  = errors.New("file path cannot contain an empty directory")
	errBadFilename     = errors.New("file name must be relative, without . or .. segments")
	errFilePersisted   = errors.New("file is persisted")
	errFileAborted     = errors.New("file is aborted")
)
