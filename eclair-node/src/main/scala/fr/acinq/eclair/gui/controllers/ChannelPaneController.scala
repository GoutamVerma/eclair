package fr.acinq.eclair.gui.controllers

import javafx.beans.value.{ChangeListener, ObservableValue}
import javafx.fxml.FXML
import javafx.scene.control.{Button, ContextMenu, ProgressBar, TextField}
import javafx.scene.input.{ContextMenuEvent, MouseEvent}

import fr.acinq.eclair.channel.LocalParams
import fr.acinq.eclair.gui.utils.{ContextMenuUtils, CopyAction}
import grizzled.slf4j.Logging

/**
  * Created by DPA on 23/09/2016.
  */
class ChannelPaneController(theirNodeIdValue: String, channelParams: LocalParams) extends Logging {

  @FXML var channelId: TextField = _
  @FXML var balanceBar: ProgressBar = _
  @FXML var amountUs: TextField = _
  @FXML var nodeId: TextField = _
  @FXML var capacity: TextField = _
  @FXML var funder: TextField = _
  @FXML var state: TextField = _
  @FXML var close: Button = _

  var contextMenu: ContextMenu = _

  private def buildChannelContextMenu = {
    contextMenu = ContextMenuUtils.buildCopyContext(List(
      new CopyAction("Copy Channel Id", channelId.getText),
      new CopyAction("Copy Node Pubkey", theirNodeIdValue)
    ))
    contextMenu.getStyleClass.add("context-channel")
    channelId.setContextMenu(contextMenu)
    amountUs.setContextMenu(contextMenu)
    nodeId.setContextMenu(contextMenu)
    capacity.setContextMenu(contextMenu)
    funder.setContextMenu(contextMenu)
    state.setContextMenu(contextMenu)
  }

  @FXML def initialize = {
    channelId.textProperty().addListener(new ChangeListener[String] {
      override def changed(observable: ObservableValue[_ <: String], oldValue: String, newValue: String) = buildChannelContextMenu
    })
    buildChannelContextMenu
  }

  @FXML def openChannelContext(event: ContextMenuEvent) {
    contextMenu.show(channelId, event.getScreenX, event.getScreenY)
    event.consume
  }

  @FXML def closeChannelContext(event: MouseEvent) {
    if (contextMenu != null) contextMenu.hide
  }
}
