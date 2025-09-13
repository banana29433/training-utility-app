const { app, BrowserWindow, ipcMain, dialog } = require('electron'),
	fs = require('fs'),
	path = require('path')

let win

function createWindow() {
	win = new BrowserWindow({
		width: 1280,
		height: 720,
		webPreferences: {
			nodeIntegration: true
		},
		title: 'Training Utility 1.10',
		frame: false,
		icon: path.join(__dirname, 'icon.png')
	})

	win.maximize()
	win.loadFile('index.html')

	win.on('closed', () => {
		win = null
	})
}

app.on('ready', createWindow)

app.on('window-all-closed', () => {
	if (process.platform !== 'darwin') {
		app.quit()
	}
})

app.on('activate', () => {
	if (win === null) {
		createWindow()
	}
})

ipcMain.on('winClose', () => {
	win.close()
})

ipcMain.on('winMin', () => {
	win.minimize()
})

ipcMain.on('winMax', () => {
	if (win.isMaximized()) win.unmaximize()
	else win.maximize()
})

const trainingsDir = path.join(process.cwd(), '/trainings'),
	templatesDir = path.join(process.cwd(), '/templates')

if (!fs.existsSync(trainingsDir)) fs.mkdir(trainingsDir, () => {})
if (!fs.existsSync(templatesDir)) fs.mkdir(templatesDir, () => {})

ipcMain.on('save', (e, type = 'training', defaultFileName, data) => {
	dialog.showSaveDialog(win, {
		defaultPath: path.join(type === 'training' ? trainingsDir : templatesDir, `${defaultFileName}.json`),
		filters: [{
			name: 'JSON',
			extensions: ['json']
		}]
	}).then(res => {
		if (res.canceled) return
		fs.writeFile(res.filePath, data, () => e.sender.send('saveSuccess', type))
	}).catch()
})

ipcMain.on('open', e => {
	dialog.showOpenDialog(win, {
		defaultPath: templatesDir,
		filters: [{
			name: 'JSON',
			extensions: ['json']
		}],
		properties: ['openFile']
	}).then(res => {
		if (res.canceled) return
		try {
			const data = JSON.parse(fs.readFileSync(res.filePaths[0]))
			e.sender.send('openSuccess', data)
		}
		catch {e.sender.send('openFail')}
	}).catch()
})

ipcMain.on('autosave', (e, data) => {
	fs.writeFile(`${trainingsDir}/autosave.json`, data, () => {})
})