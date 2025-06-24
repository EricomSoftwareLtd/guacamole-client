angular.module('client')
.directive('stickyToolbar', ['$rootScope', function($rootScope) {
    return {
        restrict: 'E', // Use as an element: <sticky-toolbar></sticky-toolbar>
        templateUrl: 'app/client/templates/guacStickyToolbar.html',
        scope: {
            focusedClient: '=' // Bind focusedClient from parent scope
        }, 
        controller: ["$scope", function($scope) {
            $scope.isExpanded = false; // Initial state

            $scope.toggleExpand = function() {
                $scope.isExpanded = !$scope.isExpanded;
            };

            // Open the built-in file transfer menu (filesystem menu)
            $scope.fileTransfer = function() {
                $rootScope.$broadcast('guacShowFilesystemMenu');
            };

            // Open the on-screen keyboard
            $scope.toggleKeyboard = function() {
                $rootScope.$broadcast('guacShowOSK');
            };

            // Send Ctrl+Alt+Delete to the focused client
            $scope.sendCtrlAltDel = function() {
                // Keysyms: Ctrl (0xFFE3), Alt (0xFFE9), Delete (0xFFFF)
                $rootScope.$broadcast('guacSyntheticKeydown', 0xFFE3); // Ctrl down
                $rootScope.$broadcast('guacSyntheticKeydown', 0xFFE9); // Alt down
                $rootScope.$broadcast('guacSyntheticKeydown', 0xFFFF); // Delete down
                $rootScope.$broadcast('guacSyntheticKeyup', 0xFFFF);   // Delete up
                $rootScope.$broadcast('guacSyntheticKeyup', 0xFFE9);   // Alt up
                $rootScope.$broadcast('guacSyntheticKeyup', 0xFFE3);   // Ctrl up
            };
        }]
    };
}]);