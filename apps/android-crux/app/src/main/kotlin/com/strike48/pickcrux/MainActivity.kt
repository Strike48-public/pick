package com.strike48.pickcrux

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.strike48.pick.shared.Event
import com.strike48.pick.shared.MessageKind
import com.strike48.pick.shared.ViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Placeholder api_url/token: real Matrix/OAuth wiring is a later task.
        // Network calls may error into ViewModel.error, which the UI renders.
        val core = NativeCore.create(
            apiUrl = "https://plg.strike48.test",
            token = "placeholder-token",
        )

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    ScanApp(core)
                }
            }
        }
    }
}

@Composable
fun ScanApp(core: NativeCore) {
    var model by remember { mutableStateOf(core.view()) }
    ScanScreen(
        model = model,
        onStartScan = { model = core.update(Event.StartScan) },
    )
}

@Composable
fun ScanScreen(model: ViewModel, onStartScan: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = "Pick — Easy Mode",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = "screen=${model.screen} - ${model.connection.label}",
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(24.dp))

        if (model.showScanCard) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        text = "Scan your network",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = "Discover hosts and services on the local network.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Spacer(Modifier.height(16.dp))
                    Button(
                        onClick = onStartScan,
                        enabled = !model.scanInProgress,
                    ) {
                        Text(if (model.scanInProgress) "Scanning..." else "Scan My Network")
                    }
                }
            }
        }

        if (model.scanInProgress) {
            Spacer(Modifier.height(24.dp))
            CircularProgressIndicator()
            Spacer(Modifier.height(8.dp))
            Text("Scan in progress", style = MaterialTheme.typography.bodyMedium)
        }

        model.error?.let { err ->
            Spacer(Modifier.height(24.dp))
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text(
                        "Error",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(err, style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        if (model.messages.isNotEmpty()) {
            Spacer(Modifier.height(24.dp))
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                model.messages.forEach { msg ->
                    val prefix = when (msg.kind) {
                        MessageKind.USER -> "you"
                        MessageKind.AGENTTEXT -> "agent"
                        MessageKind.TOOLCALL -> "tool"
                    }
                    Text(
                        text = "[$prefix] ${msg.markdown}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }
}
